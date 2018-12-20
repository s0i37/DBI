#include <pin.H>
#include <stdio.h>
#include <list>
#include <iostream>

#define VERSION "0.19"
#define FUZZ_DATA_SIZE 0x1000
#define MAP_SIZE    (1 << 16)

#if defined(__i386__) || defined(_WIN32)
    #define HEX_FMT "0x%08x"
    #define INT_FMT "%u"
#endif
#if defined(__x86_64__) || defined(_WIN64)
    #define HEX_FMT "0x%016lx"
    #define INT_FMT "%lu"
#endif

#include <sys/shm.h>
#include <sys/wait.h>
#include <unistd.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
int afl_sync_fd = -1;
int afl_data_fd = -1;
bool read_from_pipe();
bool write_to_pipe(char *);


CONTEXT snapshot;
BOOL is_saved_snapshot = FALSE;
BOOL in_fuzz_area = FALSE;
BOOL was_crash = FALSE;
ADDRINT min_addr = 0;
ADDRINT max_addr = 0;
ADDRINT entry_addr = 0;
ADDRINT exit_addr = 0;
string need_module;
unsigned char original_fuzzed_data[FUZZ_DATA_SIZE];
unsigned int previous_fuzz_data_len = 0;

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


VOID get_fuzz_data();

void FUZZ(CONTEXT *ctx)
{
    unsigned int i;
    if(Knob_debug)
      printf("[*] waiting of fuzz data\n");
	get_fuzz_data(); /* WAIT */
	ADDRINT data_pointer = PIN_GetContextReg(ctx, REG_GAX);

    /* save virgin data values */
    for(i = previous_fuzz_data_len; i < fuzz_data.len; i++)
        original_fuzzed_data[i] = ((unsigned char *)data_pointer)[i];

    /* insert fuzz data values */
	for(i = 0; i < fuzz_data.len; i++)
		((unsigned char *)data_pointer)[i] = ((char *)fuzz_data.data)[i];

    /* restore rewritten data values after fuzz data */
    for(i = fuzz_data.len; i < previous_fuzz_data_len; i++)
        ((unsigned char *)data_pointer)[i] = original_fuzzed_data[i];

    previous_fuzz_data_len = fuzz_data.len;
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


VOID fuzzer_synchronization(char *cmd)
{
    write_to_pipe(cmd);
}

VOID get_fuzz_data()
{
    while(1)
    {
        int result;
        result = read_from_pipe();
        if(! result)
        {
            if (Knob_debug)
                printf("[*] reopen afl_data\n");
            close(afl_data_fd);
            afl_data_fd = open("afl_data", O_RDONLY);
        }
        else
            break;
    }
    //printf("fuzz_data.len = %d\n", fuzz_data.len);
    //write(1, fuzz_data.data, fuzz_data.len);
}

void exec_instr(ADDRINT addr, CONTEXT * ctx)
{
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
        fuzzer_synchronization( (char *) "e" );
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


void reopen_pipe(int signal)
{
    if (Knob_debug)
        printf("[*] reopen afl_sync\n");
    afl_sync_fd = open("afl_sync", O_WRONLY);
}
bool write_to_pipe(char *cmd)
{
    if(afl_sync_fd == -1)
        afl_sync_fd = open("afl_sync", O_WRONLY);
    write(afl_sync_fd, cmd, 1); /* SIGPIPE */
    return true;
}
bool read_from_pipe()
{
    if(afl_data_fd == -1)
       afl_data_fd = open("afl_data", O_RDONLY);

    fuzz_data.len = read(afl_data_fd, fuzz_data.data, FUZZ_DATA_SIZE);
    if( (int)fuzz_data.len == 0 )
        return false;
    if(Knob_debug)
    {
        //write(1, "[+] fuzz data: ", sizeof("[+] fuzz data: "));
        //write(1, fuzz_data.data, fuzz_data.len);
        printf("[+] fuzz data %d bytes\n", fuzz_data.len);
    }
    return true;
}

bool setup_shm() {
    if (char *shm_key_str = getenv("__AFL_SHM_ID"))
    {
        int shm_id, shm_key;
        shm_key = atoi(shm_key_str);
        if(Knob_debug)
            printf("[*] shm_key: %d\n", shm_key);
	
        if( ( shm_id = shmget( (key_t)shm_key, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600 ) ) < 0 )  // try create by key
            shm_id = shmget( (key_t)shm_key, MAP_SIZE, IPC_EXCL | 0600 );  // find by key
        bitmap_shm = (uint8_t*)(shmat(shm_id, 0, 0));
        
        if (bitmap_shm == (void *)(-1))
        {
            printf("[!] failed to get shm addr from shmmat()\n");
            return false;
        }
    }
    else
    {
        printf("[!] failed to get shm_id envvar\n");
        return false;
    }
    return true;
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

bool on_crash(unsigned int threadId, int sig, CONTEXT* ctx, bool hasHandler, const EXCEPTION_INFO* pExceptInfo, void* v)
{
    if(Knob_debug)
    {
        printf("[!] signal %d\n", sig);
        dump_registers(ctx);
    }
    was_crash = true;
    fuzzer_synchronization( (char *) "c" );
    return false;            /* no pass signal to application */
}

EXCEPT_HANDLING_RESULT internal_exception(THREADID tid, EXCEPTION_INFO *pExceptInfo, PHYSICAL_CONTEXT *pPhysCtxt, VOID *v)
{
  if (Knob_debug)
     printf( "[!] internal_exception in " HEX_FMT "\n", PIN_GetPhysicalContextReg(pPhysCtxt, REG_INST_PTR) );
  return EHR_HANDLED;
}

VOID entry_point(VOID *ptr)
{
    IMG img;
    SEC sec;
    for(img = APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img))
    {
        if( need_module != "" && strcasestr( IMG_Name(img).c_str(), need_module.c_str() ) == 0 )
            continue;
        if(Knob_debug)
            printf("[*] module %s " HEX_FMT " " HEX_FMT "\n", IMG_Name(img).c_str(), IMG_LowAddress(img), IMG_HighAddress(img));
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
    std::cerr << "   -module module --  module for coverage" << std::endl;
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

    setup_shm();
    signal(SIGPIPE, reopen_pipe);

    entry_addr = Knob_entry.Value();
    exit_addr = Knob_exit.Value();
    need_module = Knob_module.Value();

	INS_AddInstrumentFunction(ins_instrument, 0);
	TRACE_AddInstrumentFunction(trace_intrument, 0);
    PIN_InterceptSignal(SIGSEGV, on_crash, 0);
	//PIN_AddInternalExceptionHandler(internal_exception, 0);
	PIN_AddApplicationStartFunction(entry_point, 0);
	PIN_AddFiniFunction(fini, 0);
	PIN_StartProgram();
	return 0;
}

/*
    linux named pipe performance: > 1M/s
    pure PIN in-memory speed: 50k/s
    this module speed: ~30k/s
*/
