#include <pin.H>
#include <stdio.h>
#include <list>
#include <iostream>

#define VERSION "0.23"
#define MAP_SIZE    (1 << 16)

#if defined(__i386__) || defined(_WIN32)
    #define HEX_FMT "0x%08x"
    #define INT_FMT "%u"
#endif
#if defined(__x86_64__) || defined(_WIN64)
    #define HEX_FMT "0x%016lx"
    #define INT_FMT "%lu"
#endif


namespace windows {
    #include <Windows.h>
    HANDLE pipe_sync;
    OVERLAPPED pipe_overlapped;
    BOOL has_pipe_sync_connected = FALSE;
    void write_to_pipe(char *);
    void get_fuzz_data();
}


CONTEXT snapshot;
BOOL is_saved_snapshot = FALSE;
BOOL in_fuzz_area = FALSE;
BOOL was_crash = FALSE;
BOOL is_loop = FALSE;
ADDRINT min_addr = 0;
ADDRINT max_addr = 0;
ADDRINT entry_addr = -1;
ADDRINT exit_addr = -1;
string target_module;
string coverage_module;
unsigned int previous_fuzz_data_len = 0;

unsigned char bitmap[MAP_SIZE];
const char *shm_str;
uint8_t *bitmap_shm = 0;
ADDRINT last_id = 0;
UINT32 worker_thread_id = 0;

long unsigned int fuzz_iters = 0;
struct FuzzData
{
	void *data;
	UINT32 len;
} fuzz_data;

struct memoryInput
{
  ADDRINT addr;
  #if defined(__i386__) || defined(_WIN32)
  UINT32 val;
  #elif defined(__x86_64__) || defined(_WIN64)
  UINT64 val;
  #endif
};
list<struct memoryInput> memInput;

FILE * f;

KNOB<BOOL> Knob_debug(KNOB_MODE_WRITEONCE,  "pintool", "debug", "0", "Enable debug mode");
KNOB<string> Knob_target_module(KNOB_MODE_WRITEONCE, "pintool", "target_module", "", "module for fuzzing");
KNOB<ADDRINT> Knob_entry(KNOB_MODE_WRITEONCE, "pintool", "entry", "-1", "start address for fuzzing");
KNOB<ADDRINT> Knob_exit(KNOB_MODE_WRITEONCE, "pintool", "exit", "-1", "stop address for fuzzing");
KNOB<string> Knob_coverage_module(KNOB_MODE_WRITEONCE, "pintool", "coverage_module", "", "module for coverage");
KNOB<string> Knob_shm_str(KNOB_MODE_WRITEONCE, "pintool", "shm", "0", "coverage shared memory string");
KNOB<BOOL> Knob_loop(KNOB_MODE_WRITEONCE,  "pintool", "loop", "0", "force loop execution flow between entry and exit points");



void restore_memory(void)
{
  list<struct memoryInput>::iterator i;

  for(i = memInput.begin(); i != memInput.end(); ++i)
  {
    *(reinterpret_cast<ADDRINT*>(i->addr)) = i->val;
    if (Knob_debug)
        fprintf(f,"[*] restore " HEX_FMT " <- " HEX_FMT "\n", i->addr, i->val);
  }
  memInput.clear();
}

void write_mem(ADDRINT addr, ADDRINT memop)
{
  struct memoryInput elem;

  if( !(is_loop && in_fuzz_area) )
    return;
  elem.addr = memop;
  elem.val = *(reinterpret_cast<ADDRINT*>(memop));
  memInput.push_back(elem);
  if (Knob_debug)
    fprintf(f,"[*] memory write " HEX_FMT ": " HEX_FMT "\n", elem.addr, elem.val);
}

inline ADDRINT valid_addr(ADDRINT addr)
{
    if ( addr >= min_addr && addr <= max_addr )
        return true;

    return false;
}


void exec_instr(ADDRINT addr, UINT32 thread_id, CONTEXT * ctx)
{
	//if( addr >= 0x401000 && addr <= 0x401024 )
	//printf(HEX_FMT "\n", addr - min_addr);
    char command;
    ADDRINT rva = addr - min_addr;

    if(was_crash && is_loop)
    {
        was_crash = false;
        in_fuzz_area = FALSE;
        PIN_SaveContext(&snapshot, ctx);
        restore_memory();
        PIN_ExecuteAt(ctx);
    }

	if(rva == entry_addr && in_fuzz_area == FALSE)
	{
        worker_thread_id = thread_id;
        in_fuzz_area = TRUE;
        if(is_loop)
        {
		  PIN_SaveContext(ctx, &snapshot);
		  is_saved_snapshot = TRUE;
        }
        if (Knob_debug)
		  fprintf(f, "[*] fuzz iteration " INT_FMT " started [%d]\n", ++fuzz_iters, worker_thread_id);
	}
	else if(rva == exit_addr && in_fuzz_area == TRUE)
	{
        in_fuzz_area = FALSE;
        if (Knob_debug)
          fprintf(f, "[*] fuzz iteration " INT_FMT " finished\n", fuzz_iters);
        windows::write_to_pipe("K");
        if(is_loop)
        {
		  if(is_saved_snapshot)
		      PIN_SaveContext(&snapshot, ctx);
		  is_saved_snapshot = FALSE;
		  restore_memory();
		  PIN_ExecuteAt(ctx);
        }
	}
}

VOID track_branch(ADDRINT cur_addr, UINT32 thread_id)
{
    ADDRINT cur_id = cur_addr - min_addr;

    if(in_fuzz_area && worker_thread_id == thread_id)
    {
        if (Knob_debug)
        {
            fprintf(f, "[+] branch: " HEX_FMT ", rel_addr: 0x%08x, index: 0x%04x\n",
                cur_addr, (UINT32)(cur_addr - min_addr), (UINT16)((cur_id ^ last_id) % MAP_SIZE) );
        }
        if (bitmap_shm != 0){
            bitmap_shm[((cur_id ^ last_id) % MAP_SIZE)]++;
        }
        else {
            bitmap[((cur_id ^ last_id) % MAP_SIZE)]++;
        }
    }
    last_id = cur_id;
}


void ins_instrument(INS ins, VOID *v)
{
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)exec_instr,
					IARG_ADDRINT, INS_Address(ins),
                    IARG_UINT32, PIN_ThreadId(),
					IARG_CONTEXT,
					IARG_END);

	if(INS_MemoryOperandIsWritten(ins, 0))
	{
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)write_mem,
					IARG_ADDRINT, INS_Address(ins),
					IARG_MEMORYOP_EA, 0,
					IARG_END);
	}
}

VOID trace_intrument(TRACE trace, VOID *v)
{
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
        {
            if (valid_addr(INS_Address(ins)))
            {
                if (INS_IsBranch(ins)) {
                    if (INS_HasFallThrough(ins) || INS_IsCall(ins))
                    {
                        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)track_branch,
                            IARG_INST_PTR,
                            IARG_UINT32, PIN_ThreadId(),
                            IARG_END);
                    }
                }
            }
        }
    }
}


namespace windows {
    void write_to_pipe(char *cmd)
    {
        DWORD num_written;
        WriteFile(pipe_sync, cmd, 1, &num_written, NULL);
    }

    BOOL setup_pipe()
    {
        /* open existent pipe */

        pipe_sync = CreateFile(
             "\\\\.\\pipe\\afl_sync",       // pipe name
             GENERIC_READ | GENERIC_WRITE,  // read and write access
             0,                             // no sharing
             NULL,                          // default security attributes
             OPEN_EXISTING,                 // opens existing pipe
             0,                             // default attributes
             NULL);
        return (pipe_sync != INVALID_HANDLE_VALUE) ? true : false;
    }

    BOOL setup_shm(const char *shm_str)
    {
        HANDLE map_file;
                   
        /* open existent shared memory */
        map_file = OpenFileMapping(
                FILE_MAP_READ | FILE_MAP_WRITE,
                FALSE, 
                shm_str);                // name of mapping object

        bitmap_shm = (unsigned char *) MapViewOfFile(map_file, // handle to map object
                FILE_MAP_ALL_ACCESS,  // read/write permission
                0,
                0,
                MAP_SIZE);

        if(!bitmap_shm)
            return false;

        memset(bitmap_shm, '\x00', MAP_SIZE);
        return true;
    }
}

void dump_registers(CONTEXT *ctx)
{
    ADDRINT rax = PIN_GetContextReg(ctx, REG_GAX);
    ADDRINT rcx = PIN_GetContextReg(ctx, REG_GCX);
    ADDRINT rdx = PIN_GetContextReg(ctx, REG_GDX);
    ADDRINT rbx = PIN_GetContextReg(ctx, REG_GBX);
    ADDRINT rsp = PIN_GetContextReg(ctx, REG_STACK_PTR);
    ADDRINT rbp = PIN_GetContextReg(ctx, REG_GBP);
    ADDRINT rsi = PIN_GetContextReg(ctx, REG_GSI);
    ADDRINT rdi = PIN_GetContextReg(ctx, REG_GDI);
    ADDRINT rip = PIN_GetContextReg(ctx, REG_IP);
    fprintf(f,"RAX: " HEX_FMT "\n"
        "RCX: " HEX_FMT "\n"
        "RDX: " HEX_FMT "\n"
        "RBX: " HEX_FMT "\n"
        "RSP: " HEX_FMT "\n"
        "RBP: " HEX_FMT "\n"
        "RSI: " HEX_FMT "\n"
        "RDI: " HEX_FMT "\n"
        "RIP: " HEX_FMT "\n"
        , rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, rip);
}

void context_change(THREADID tid, CONTEXT_CHANGE_REASON reason, const CONTEXT *ctxtFrom, CONTEXT *ctxtTo, INT32 info, VOID *v)
{
    if(reason == CONTEXT_CHANGE_REASON_EXCEPTION)
    {
        if (Knob_debug)
        {
            fprintf(f,"[!] exception " HEX_FMT "\n", info);
            dump_registers(ctxtTo);
        }
        if(info == 0xc0000005)
        {
            windows::write_to_pipe("C");
            was_crash = true;
        }
    }
}

EXCEPT_HANDLING_RESULT internal_exception(THREADID tid, EXCEPTION_INFO *pExceptInfo, PHYSICAL_CONTEXT *pPhysCtxt, VOID *v)
{
  if (Knob_debug)
     fprintf(f, "[!] internal_exception in " HEX_FMT "\n", PIN_GetPhysicalContextReg(pPhysCtxt, REG_INST_PTR) );
  return EHR_HANDLED;
}

VOID entry_point(VOID *ptr)
{
    IMG img;
    SEC sec;
    for(img = APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img))
    {
        if( target_module != "" && strcasestr( IMG_Name(img).c_str(), target_module.c_str() ) == 0 )
            continue;
        if(Knob_debug)
           fprintf(f,"[*] module %s %lx " HEX_FMT "\n", IMG_Name(img).c_str(), IMG_LowAddress(img), IMG_HighAddress(img));
        for(sec= IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
        {
            if ( SEC_IsExecutable(sec) && SEC_Name(sec) == ".text")
            {
                ADDRINT sec_addr = SEC_Address(sec);
                UINT32 sec_size = SEC_Size(sec);
                
                if(Knob_debug)
                    fprintf(f,"[*] section: %s, addr: " HEX_FMT ", size: " INT_FMT "\n", SEC_Name(sec).c_str(), sec_addr, sec_size);

                if(sec_addr != 0)
                {
                    ADDRINT high_addr = sec_addr + sec_size;

                    if(sec_addr > min_addr || min_addr == 0)
                        min_addr = sec_addr;

                    if(sec_addr > max_addr || max_addr == 0)
                        max_addr = sec_addr;

                    if(high_addr > max_addr)
                        max_addr = high_addr;

                    min_addr >>= 12;
                    min_addr <<= 12;
                    max_addr |= 0xfff;
                }
            }
        }
    }
    if(Knob_debug)
    {
        fprintf(f,"[+] min_addr: " HEX_FMT "\n", min_addr);
        fprintf(f,"[+] max_addr: " HEX_FMT "\n", max_addr);
        if(entry_addr != -1)
            fprintf(f,"[+] entry_addr: " HEX_FMT "\n", min_addr + entry_addr);
        fprintf(f,"[+] exit_addr: " HEX_FMT "\n", min_addr + exit_addr);
    }
    fflush(f);
}

void fini(INT32 code, VOID *v)
{
    if (Knob_debug)
	   fprintf(f, "[*] end\n");
    windows::DisconnectNamedPipe(windows::pipe_sync);
    windows::CloseHandle(windows::pipe_sync);
	fflush(f);
	fclose(f);
}

INT32 Usage()
{
    std::cerr << "   -debug --  prints extra debug information" << std::endl;
    std::cerr << "   -target_module module.exe --  module for fuzzing" << std::endl;
    std::cerr << "   -entry 0xADDR --  start address for fuzzing" << std::endl;
    std::cerr << "   -exit 0xADDR --  stop address for fuzzing" << std::endl;
    std::cerr << "   -coverage_module module.dll --  module for coverage" << std::endl;
    std::cerr << "   -shm afl_shm_12345 --  coverage shared memory string" << std::endl;
    std::cerr << "   -loop --  force loop execution flow between entry and exit points" << std::endl;
    return -1;
}

int main(int argc, char ** argv)
{
	f = fopen("fuzz.log", "w");
	if(PIN_Init(argc, argv))
        return Usage();

    shm_str = Knob_shm_str.Value().c_str();
    entry_addr = Knob_entry.Value();
    exit_addr = Knob_exit.Value();
    target_module = Knob_target_module.Value();
    coverage_module = Knob_coverage_module.Value();
    is_loop = Knob_loop;

    if(!windows::setup_pipe())
    {
        printf("[!] setup_pipe() problem\n");
        return 1;
    }
    if(!windows::setup_shm(shm_str))
    {
        printf("[!] setup_shm(%s) problem\n", shm_str);
        return 1;
    }


	INS_AddInstrumentFunction(ins_instrument, 0);
	TRACE_AddInstrumentFunction(trace_intrument, 0);
    PIN_AddContextChangeFunction(context_change, 0);
	//PIN_AddInternalExceptionHandler(internal_exception, 0);
	PIN_AddApplicationStartFunction(entry_point, 0);
	PIN_AddFiniFunction(fini, 0);
	PIN_StartProgram();
	return 0;
}
