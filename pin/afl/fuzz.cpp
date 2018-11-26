#include <pin.H>
#include <stdio.h>
#include <list>
#include <iostream>

#define VERSION "0.14"
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
#elif defined(__x86_64__) || defined(_WIN64)
    #define HEX_FMT "0x%016lx"
    #define INT_FMT "%lu"
#endif

#ifdef __linux__
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
#elif __win__
    namespace windows {
        #include <Windows.h>
        bool read_from_pipe();
        bool write_to_pipe(char *);
    }
#endif

CONTEXT snapshot;
BOOL is_saved_snapshot = FALSE;
BOOL in_fuzz_area = FALSE;
BOOL was_crash = FALSE;
ADDRINT min_addr = 0;
ADDRINT max_addr = 0;
ADDRINT entry_addr = 0;
ADDRINT exit_addr = 0;

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

/*
void randomizeREG(CONTEXT * ctx, ADDRINT nextAddr)
{
	PIN_SetContextReg(ctx, REG_EDX, fuzz_iters);
}
*/

VOID get_fuzz_data();

void FUZZ(CONTEXT *ctx)
{
    if(Knob_debug)
      printf("[*] waiting of fuzz data\n");
	get_fuzz_data(); /* WAIT */
	ADDRINT eax = PIN_GetContextReg(ctx, REG_GAX);
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

// afl/wrap ожидает конец обработки в target
VOID fuzzer_synchronization(char *cmd)
{
    #ifdef __win__
    windows::write_to_pipe(cmd);
    #elif __linux__
    write_to_pipe(cmd);
    #endif
}
// target/instrumentation ожидает новых данных от afl/wrap через pipe
VOID get_fuzz_data()
{
    #ifdef __win__
    windows::read_from_pipe();
    #elif __linux__
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
    #endif
}

void exec_instr(ADDRINT addr, CONTEXT * ctx)
{
	//if( addr >= 0x401000 && addr <= 0x401024 )
	//printf(HEX_FMT "\n", addr - min_addr);

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
		  printf("[+] fuzz iteration: " INT_FMT "\n", ++fuzz_iters);
		FUZZ(ctx); /* WAIT */
    	PIN_ExecuteAt(ctx);
	}
	else if(addr - min_addr == exit_addr && in_fuzz_area == TRUE)
	{
		in_fuzz_area = FALSE;
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


#ifdef __win__
namespace windows {
    bool write_to_pipe(char *cmd)
    {
        DWORD bytes_writen;
        HANDLE afl_sync_handle;
        afl_sync_handle = CreateFile(
            "\\\\.\\pipe\\afl_sync",    // pipe name
            GENERIC_READ |              // read and write access
            GENERIC_WRITE,
            0,                          // no sharing
            NULL,                       // default security attributes
            OPEN_EXISTING,              // opens existing pipe
            0,                          // default attributes
            NULL);                                              // default security attribute

        if( afl_sync_handle == INVALID_HANDLE_VALUE )
            return false;

        WriteFile(afl_sync_handle, cmd, 1, &bytes_writen, 0);
        CloseHandle(afl_sync_handle);
        return true;
    }
    bool read_from_pipe()
    {
    	HANDLE afl_data_handle;
    	afl_data_handle = CreateNamedPipe(
	        "\\\\.\\pipe\\afl_data",                            // pipe name
	        PIPE_ACCESS_DUPLEX,                                 // read/write access
	        PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE|PIPE_WAIT,  // no wait incoming pipe connections
	        PIPE_UNLIMITED_INSTANCES,                           // max. instances
	        512,                                                // output buffer size
	        512,                                                // input buffer size
	        0,                                                  // client time-out
	        0);
    	if(! ConnectNamedPipe(afl_data_handle, NULL) ) 			/* WAIT */
    	ReadFile(afl_data_handle, &fuzz_data.data, FUZZ_DATA_SIZE, &fuzz_data.len, NULL);
		return true;
    }
}
#elif __linux__
void reopen_pipe(int signal)
{
    if (Knob_debug)
        printf("[*] reopen afl_sync\n");
    afl_sync_fd = open("afl_sync", O_WRONLY);
}
bool write_to_pipe(char *cmd)
{
    //if( access("afl_sync", F_OK ) == -1 )
    //    mkfifo("afl_sync", 777);  сделать RETURN
    if(afl_sync_fd == -1)
        afl_sync_fd = open("afl_sync", O_WRONLY);
    write(afl_sync_fd, cmd, 1); /* SIGPIPE */
    return true;
}
bool read_from_pipe()
{
    unsigned int num;
    if(afl_data_fd == -1)
       afl_data_fd = open("afl_data", O_RDONLY);
    fuzz_data.len = 0;
    while( ( num = read(afl_data_fd, fuzz_data.data, FUZZ_DATA_SIZE)) > 0 ) /* WAIT */
   	{
        fuzz_data.len += num;
    }
    if( (int)fuzz_data.len == 0 )
        return false;
    if(Knob_debug)
    {
        write(1, "[+] fuzz data: ", sizeof("[+] fuzz data: "));
        write(1, fuzz_data.data, fuzz_data.len);
    }
    return true;
}
#endif

#ifdef __win__
namespace windows {
    bool setup_shm()
    {
        HANDLE map_file;
        map_file = CreateFileMapping(
                    INVALID_HANDLE_VALUE,    // use paging file
                    NULL,                    // default security
                    PAGE_READWRITE,          // read/write access
                    0,                       // maximum object size (high-order DWORD)
                    MAP_SIZE,                // maximum object size (low-order DWORD)
                    (char *)"Local\\winapi-shm-1337");

        bitmap_shm = (unsigned char *) MapViewOfFile(map_file, // handle to map object
                FILE_MAP_ALL_ACCESS,  // read/write permission
                0,
                0,
                MAP_SIZE);
        memset(bitmap_shm, '\x00', MAP_SIZE);
        return true;
    }
}
#elif __linux__
bool setup_shm() {
    if (char *shm_key_str = getenv("__AFL_SHM_ID")) {
        int shm_id, shm_key;
        shm_key = atoi(shm_key_str);
        if(Knob_debug)
            std::cout << "[*] shm_key: " << shm_key << std::endl;        
	
        if( ( shm_id = shmget( (key_t)shm_key, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600 ) ) < 0 )  // try create by key
            shm_id = shmget( (key_t)shm_key, MAP_SIZE, IPC_EXCL | 0600 );  // find by key
        bitmap_shm = reinterpret_cast<uint8_t*>(shmat(shm_id, 0, 0));
        
        if (bitmap_shm == reinterpret_cast<void *>(-1)) {
            std::cout << "failed to get shm addr from shmmat()" << std::endl;
            return false;
        }
    }
    else {
        std::cout << "failed to get shm_id envvar" << std::endl;
        return false;
    }
    return true;
}
#endif

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

#ifdef __win__
void context_change(THREADID tid, CONTEXT_CHANGE_REASON reason, const CONTEXT *ctxtFrom, CONTEXT *ctxtTo, INT32 info, VOID *v)
{
    if(reason == CONTEXT_CHANGE_REASON_EXCEPTION)
    {
        if (Knob_debug)
        {
            printf("[!] exception " HEX_FMT "\n", info);
            dump_registers(ctx);
        }
        if(info == 0xc0000005)
            windows::write_to_pipe("c");
    }
}
#elif __linux__
bool on_crash(unsigned int threadId, int sig, CONTEXT* ctx, bool hasHandler, const EXCEPTION_INFO* pExceptInfo, void* v)
{
    if(Knob_debug)
    {
        printf("[!] signal %d\n", sig);
        dump_registers(ctx);
    }
    was_crash = true;
    write_to_pipe( (char *) "c" );
    return false;            /* no pass signal to application */
}
#endif

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

    IMG img = APP_ImgHead();
    for(SEC sec= IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {
        // lets sanity check the exec flag 
        // TODO: the check for .text name might be too much, there could be other executable segments we
        //       need to instrument but maybe not things like the .plt or .fini/init
        // IF this changes, we need to change the code in the instrumentation code, save all the base addresses.

        if (SEC_IsExecutable(sec) && SEC_Name(sec) == ".text")
        {
            ADDRINT sec_addr = SEC_Address(sec);
            UINT64  sec_size = SEC_Size(sec);
            
            if (Knob_debug)
            {
                std::cout << "[*] Name: " << SEC_Name(sec) << std::endl;
                std::cout << "[*] Addr: 0x" << std::hex << sec_addr << std::endl;
                std::cout << "[*] Size: " << sec_size << std::endl << std::endl;
            }

            if (sec_addr != 0)
            {
                ADDRINT high_addr = sec_addr + sec_size;

                if (sec_addr > min_addr || min_addr == 0)
                    min_addr = sec_addr;

                // Now check and set the max_addr.
                if (sec_addr > max_addr || max_addr == 0)
                    max_addr = sec_addr;

                if (high_addr > max_addr)
                    max_addr = high_addr;

                min_addr >>= 12;
                min_addr <<= 12;
                max_addr |= 0xfff;
            }
        }
    }
    if (Knob_debug)
    {
        std::cout << "[*] min_addr:\t0x" << std::hex << min_addr << std::endl;
        std::cout << "[*] max_addr:\t0x" << std::hex << max_addr << std::endl;
        std::cout << "[*] entry_addr:\t0x" << std::hex << min_addr + entry_addr << std::endl;
        std::cout << "[*] exit_addr:\t0x" << std::hex << min_addr + exit_addr << std::endl << std::endl;
    }   
}

void fini(INT32 code, VOID *v)
{
    if (Knob_debug)
	   printf("[*] end\n");
	fflush(f);
	fclose(f);
}

INT32 Usage()
{
    std::cerr << "in-memory fuzzer -- A pin tool to enable blackbox binaries to be fuzzed with AFL on Linux/Windows" << std::endl;
    std::cerr << "   -debug --  prints extra debug information." << std::endl;
    std::cerr << "   -entry 0xADDR --  start address for coverage signal." << std::endl;
    std::cerr << "   -exit 0xADDR --  stop address for coverage signal." << std::endl;
    return -1;
}

int main(int argc, char ** argv)
{
	f = fopen("fuzz.log", "w");
	if(PIN_Init(argc, argv)){
        return Usage();
    }

    fuzz_data.data = malloc(FUZZ_DATA_SIZE);

	#ifdef __win__
    windows::setup_shm();
    #elif __linux__
    setup_shm();
    signal(SIGPIPE, reopen_pipe);
    #endif

    entry_addr = Knob_entry.Value();
    exit_addr = Knob_exit.Value();

	INS_AddInstrumentFunction(ins_instrument, 0);
	TRACE_AddInstrumentFunction(trace_intrument, 0);
	#ifdef __win__
    PIN_AddContextChangeFunction(context_change, 0);
    #elif __linux__
    PIN_InterceptSignal(SIGSEGV, on_crash, 0);
    #endif
	//PIN_AddInternalExceptionHandler(internal_exception, 0);
	PIN_AddApplicationStartFunction(entry_point, 0);
	PIN_AddFiniFunction(fini, 0);
	PIN_StartProgram();
	return 0;
}