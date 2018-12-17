#include <pin.H>
#include <stdio.h>
#include <list>
#include <iostream>

#define VERSION "0.17"
#define FUZZ_DATA_SIZE 0x1000
#define MAP_SIZE    (1 << 16)

#ifdef _WIN64
    #define __win__ 1
#elif _WIN32
    #define __win__ 1
#endif

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
    HANDLE pipe_sync = INVALID_HANDLE_VALUE, pipe_data;
    char read_from_pipe();
    void write_to_pipe(char);
    void get_fuzz_data();
}


CONTEXT snapshot;
BOOL is_saved_snapshot = FALSE;
BOOL in_fuzz_area = FALSE;
BOOL was_crash = FALSE;
ADDRINT min_addr = 0;
ADDRINT max_addr = 0;
ADDRINT entry_addr = 0;
ADDRINT exit_addr = 0;
string need_module;

unsigned char bitmap[MAP_SIZE];
uint8_t *bitmap_shm = 0;
ADDRINT last_id = 0;

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
KNOB<ADDRINT> Knob_entry(KNOB_MODE_WRITEONCE, "pintool", "entry", "0", "start address for coverage signal");
KNOB<ADDRINT> Knob_exit(KNOB_MODE_WRITEONCE, "pintool", "exit", "0", "stop address for coverage signal");
KNOB<string> Knob_module(KNOB_MODE_WRITEONCE, "pintool", "module", "", "fuzz just this module");

/*
void randomizeREG(CONTEXT * ctx, ADDRINT nextAddr)
{
	PIN_SetContextReg(ctx, REG_EDX, fuzz_iters);
}
*/

void FUZZ(CONTEXT *ctx)
{
    if(Knob_debug)
      printf("[*] waiting of fuzz data\n");
	windows::get_fuzz_data(); /* WAIT */
	ADDRINT eax = PIN_GetContextReg(ctx, REG_GCX);
	for(unsigned int i = 0; i < fuzz_data.len; i++)
		((unsigned char *)eax)[i] = ((char *)fuzz_data.data)[i];
}

void restore_memory(void)
{
  list<struct memoryInput>::iterator i;

  for(i = memInput.begin(); i != memInput.end(); ++i)
  {
    *(reinterpret_cast<ADDRINT*>(i->addr)) = i->val;
    if (Knob_debug)
        printf("[*] restore " HEX_FMT " <- " HEX_FMT "\n", i->addr, i->val);
  }
  memInput.clear();
}

void write_mem(ADDRINT addr, ADDRINT memop)
{
  struct memoryInput elem;

  if(! in_fuzz_area)
  	return;
  elem.addr = memop;
  elem.val = *(reinterpret_cast<ADDRINT*>(memop));
  memInput.push_back(elem);
  if (Knob_debug)
    printf("[*] memory write " HEX_FMT ": " HEX_FMT "\n", elem.addr, elem.val);
}

inline ADDRINT valid_addr(ADDRINT addr)
{
    if ( addr >= min_addr && addr <= max_addr )
        return true;

    return false;
}


void exec_instr(ADDRINT addr, CONTEXT * ctx)
{
	//if( addr >= 0x401000 && addr <= 0x401024 )
	//printf(HEX_FMT "\n", addr - min_addr);
    char command;

    if(was_crash)
    {
        was_crash = false;
        in_fuzz_area = FALSE;
        PIN_SaveContext(&snapshot, ctx);
        restore_memory();
        PIN_ExecuteAt(ctx);
    }

	if(addr - min_addr == entry_addr && in_fuzz_area == FALSE)
	{
        windows::write_to_pipe('P');
        command = windows::read_from_pipe();
        if(command == 'Q')
            PIN_ExitApplication(0);

		in_fuzz_area = TRUE;
		PIN_SaveContext(ctx, &snapshot);
		is_saved_snapshot = TRUE;
        if (Knob_debug)
		  printf("[+] fuzz iteration " INT_FMT " started\n", ++fuzz_iters);
		FUZZ(ctx); /* WAIT */
    	PIN_ExecuteAt(ctx);
	}
	else if(addr - min_addr == exit_addr && in_fuzz_area == TRUE)
	{
		in_fuzz_area = FALSE;
        if (Knob_debug)
          printf("[*] fuzz iteration " INT_FMT " finished\n", fuzz_iters);
        windows::write_to_pipe('K');
		if(is_saved_snapshot)
			PIN_SaveContext(&snapshot, ctx);
		is_saved_snapshot = FALSE;
		restore_memory();
		PIN_ExecuteAt(ctx);
	}
}

VOID track_branch(ADDRINT cur_addr)
{
    ADDRINT cur_id = cur_addr - min_addr;

    if (Knob_debug) {
        printf( "[+] branch: " HEX_FMT ", rel_addr: 0x%08x, index: 0x%04x\n",
          cur_addr, (UINT32)(cur_addr - min_addr), (UINT16)((cur_id ^ last_id) % MAP_SIZE) );
    }

    if(in_fuzz_area)
    {
        if (bitmap_shm != 0){
            bitmap_shm[((cur_id ^ last_id) % MAP_SIZE)]++;
        }
        else {
            bitmap[((cur_id ^ last_id) % MAP_SIZE)]++;
        }
    }
    last_id = cur_id;

    /*
    if(entry_addr && entry_addr == cur_id)
    {
        if(Knob_debug)
            std::cout << "entry" << std::endl;
        coverage_enable = TRUE;
    }
    else if(exit_addr && exit_addr == cur_id)
    {
        if(Knob_debug)
            std::cout << "exit" << std::endl;
        coverage_enable = FALSE;
    }
    */
}


void ins_instrument(INS ins, VOID *v)
{
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)exec_instr,
					IARG_ADDRINT, INS_Address(ins),
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
            // make sure it is in a segment we want to instrument!
            if (valid_addr(INS_Address(ins)))
            {
                if (INS_IsBranch(ins)) {
                    // As per afl-as.c we only care about conditional branches (so no JMP instructions)
                    if (INS_HasFallThrough(ins) || INS_IsCall(ins))
                    {
                        /*if (Knob_debug) {
                            std::cout << "BRACH: 0x" << std::hex << INS_Address(ins) << ":\t" << INS_Disassemble(ins) << std::endl;
                        }*/

                        // Instrument the code.
                        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)track_branch,
                            IARG_INST_PTR,
                            IARG_END);
                    }
                }
            }
        }
    }
}


namespace windows {
    void write_to_pipe(char cmd)
    {
        DWORD num_written;

        if(pipe_sync == INVALID_HANDLE_VALUE)
            /* open existed pipe */
            pipe_sync = CreateFile(
                "\\\\.\\pipe\\afl_pipe_default",// pipe name
                GENERIC_READ|GENERIC_WRITE,     // read and write access
                0,                              // no sharing
                NULL,                           // default security attributes
                OPEN_EXISTING,                  // opens existing pipe
                0,                              // default attributes
                NULL);

        ConnectNamedPipe(pipe_sync, NULL); /* WAIT */
        WriteFile(pipe_sync, &cmd, 1, &num_written, NULL);
        DisconnectNamedPipe(pipe_sync);

    }
    char read_from_pipe()
    {
        DWORD num_read;
        char result;

        ConnectNamedPipe(pipe_sync, NULL); /* WAIT */
        ReadFile(pipe_sync, &result, 1, &num_read, NULL);
        DisconnectNamedPipe(pipe_sync);
        return result;
    }

    // target/instrumentation WAIT новых данных от afl/wrap через pipe
    void get_fuzz_data()
    {
        ConnectNamedPipe(pipe_data, NULL); /* WAIT */
        ReadFile(pipe_data, fuzz_data.data, FUZZ_DATA_SIZE, (LPDWORD)&fuzz_data.len, NULL);
        DisconnectNamedPipe(pipe_data);
    }

    void setup_pipe()
    {
        /* create new pipe */
        pipe_sync = CreateNamedPipe(
            "\\\\.\\pipe\\afl_pipe_default",// pipe name
            PIPE_ACCESS_DUPLEX |            // read/write access 
            FILE_FLAG_OVERLAPPED,           // overlapped mode 
            0,
            1,                              // max. instances
            512,                            // output buffer size
            512,                            // input buffer size
            20000,                          // client time-out
            NULL);

        /* create new pipe */
        pipe_data = CreateNamedPipe(
            "\\\\.\\pipe\\afl_data",        // pipe name
            PIPE_ACCESS_DUPLEX |            // read/write access 
            FILE_FLAG_OVERLAPPED,           // overlapped mode 
            0,
            1,                              // max. instances
            512,                            // output buffer size
            512,                            // input buffer size
            20000,                          // client time-out
            NULL);
    }

    void setup_shm()
    {
        HANDLE map_file;
                   // (char *)"Local\\winapi-shm-1337");
        map_file = CreateFileMapping(
                   INVALID_HANDLE_VALUE,    // use paging file
                   NULL,                    // default security
                   PAGE_READWRITE,          // read/write access
                   0,                       // maximum object size (high-order DWORD)
                   MAP_SIZE,                // maximum object size (low-order DWORD)
                   (char *)"afl_shm_default");        // name of mapping object

        bitmap_shm = (unsigned char *) MapViewOfFile(map_file, // handle to map object
                FILE_MAP_ALL_ACCESS,  // read/write permission
                0,
                0,
                MAP_SIZE);
        memset(bitmap_shm, '\x00', MAP_SIZE);
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
    ADDRINT rip = PIN_GetContextReg(ctx, REG_RIP);
    printf("RAX: " HEX_FMT "\n"
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
            printf("[!] exception " HEX_FMT "\n", info);
            dump_registers(ctxtTo);
        }
        if(info == 0xc0000005)
        {
            windows::write_to_pipe('C');
            was_crash = true;
        }
    }
}

EXCEPT_HANDLING_RESULT internal_exception(THREADID tid, EXCEPTION_INFO *pExceptInfo, PHYSICAL_CONTEXT *pPhysCtxt, VOID *v)
{
  if (Knob_debug)
     printf( "[!] internal_exception in " HEX_FMT "\n", PIN_GetPhysicalContextReg(pPhysCtxt, REG_INST_PTR) );
  return EHR_HANDLED;
}

VOID entry_point(VOID *ptr)
{
    /*  Much like the original instrumentation from AFL we only want to instrument the segments of code
     *  from the actual application and not the link and PIN setup itself.
     *
     *  Inspired by: http://joxeankoret.com/blog/2012/11/04/a-simple-pin-tool-unpacker-for-the-linux-version-of-skype/
     */

    IMG img;
    SEC sec;
    for(img = APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img))
    {
        if( need_module != "" && strcasestr( IMG_Name(img).c_str(), need_module.c_str() ) == 0 )
            continue;
        if(Knob_debug)
            printf("[*] module %s %lx " HEX_FMT "\n", IMG_Name(img).c_str(), IMG_LowAddress(img), IMG_HighAddress(img));
        for(sec= IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
        {
            if ( SEC_IsExecutable(sec) /*&& SEC_Name(sec) == ".text"*/)
            {
                ADDRINT sec_addr = SEC_Address(sec);
                UINT64 sec_size = SEC_Size(sec);
                
                if(Knob_debug)
                    printf("[*] section: %s, addr: " HEX_FMT ", size: " INT_FMT "\n", SEC_Name(sec).c_str(), sec_addr, sec_size);

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
        printf("[+] min_addr: " HEX_FMT "\n", min_addr);
        printf("[+] max_addr: " HEX_FMT "\n", max_addr);
        printf("[+] entry_addr: " HEX_FMT "\n", min_addr + entry_addr);
        printf("[+] exit_addr: " HEX_FMT "\n", min_addr + exit_addr);
    }   
}

void fini(INT32 code, VOID *v)
{
    if (Knob_debug)
	   printf("[*] end\n");
	//fflush(f);
	//fclose(f);
}

INT32 Usage()
{
    std::cerr << "in-memory fuzzer -- A pin tool to enable blackbox binaries to be fuzzed with AFL on Linux/Windows" << std::endl;
    std::cerr << "   -debug --  prints extra debug information" << std::endl;
    std::cerr << "   -entry 0xADDR --  start address for coverage" << std::endl;
    std::cerr << "   -exit 0xADDR --  stop address for coverage" << std::endl;
    return -1;
}

int main(int argc, char ** argv)
{
	//f = fopen("fuzz.log", "w");
	if(PIN_Init(argc, argv))
        return Usage();

    fuzz_data.data = malloc(FUZZ_DATA_SIZE);

    windows::setup_pipe();
    windows::setup_shm();

    entry_addr = Knob_entry.Value();
    exit_addr = Knob_exit.Value();
    need_module = Knob_module.Value();

	INS_AddInstrumentFunction(ins_instrument, 0);
	TRACE_AddInstrumentFunction(trace_intrument, 0);
    PIN_AddContextChangeFunction(context_change, 0);
	//PIN_AddInternalExceptionHandler(internal_exception, 0);
	PIN_AddApplicationStartFunction(entry_point, 0);
	PIN_AddFiniFunction(fini, 0);
	PIN_StartProgram();
	return 0;
}

/*
    windows pipe performance: ~25k/s
    pure PIN in-memory speed: 15k/s
*/