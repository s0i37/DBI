#include <pin.H>
#include <string>
#include <cstdlib>
#include <iostream>

#define VERSION "0.42"

#ifdef _WIN64
    #define __win__ 1
#elif _WIN32
    #define __win__ 1
#endif

#if defined(__i386__) || defined(_WIN32)
    #define HEX_FMT "0x%08x"
    #define INT_FMT "%u"
#elif defined(__x86_64__) || defined(_WIN64)
    #define HEX_FMT "0x%08lx"
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
    bool write_to_pipe(char *);
#elif __win__
    namespace windows {
        #include <Windows.h>
        bool write_to_pipe(char *);
    }
#endif

// 65536
#define MAP_SIZE    (1 << 16)
#define FORKSRV_FD  198

//  CLI options -----------------------------------------------------------

KNOB<string> Knob_debugfile(KNOB_MODE_WRITEONCE,  "pintool", "debug", "", "Enable debug mode");
KNOB<string> Knob_module(KNOB_MODE_WRITEONCE,  "pintool", "module", "", "coverage just this module range");
KNOB<ADDRINT> Knob_exit(KNOB_MODE_WRITEONCE, "pintool", "exit", "0", "stop address for coverage signal");

//  Global Vars -----------------------------------------------------------

string cover_module;
string debug_file;
BOOL coverage_enable = TRUE;
ADDRINT min_addr = 0;
ADDRINT max_addr = 0;
ADDRINT exit_addr = 0;

unsigned char bitmap[MAP_SIZE];
uint8_t *bitmap_shm = 0;

ADDRINT last_id = 0;
FILE *f = 0;

//  inlined functions -----------------------------------------------------

inline ADDRINT valid_addr(ADDRINT addr)
{
    if ( addr >= min_addr && addr <= max_addr )
        return true;

    return false;
}

//  Inserted functions ----------------------------------------------------

VOID fuzzer_synchronization(char *cmd)
{
    #ifdef __win__
    windows::write_to_pipe(cmd);
    #elif __linux__
    write_to_pipe(cmd);
    #endif
}

// Unused currently but could become a fast call in the future once I have tested it more.
VOID TrackBranch(ADDRINT cur_addr)
{
    ADDRINT cur_id = cur_addr - min_addr;
    if(f)
    {
        fprintf(f, "0x%lx 0x%x\n", cur_addr, (UINT32)cur_id);
        fflush(f);
    }

    if (bitmap_shm != 0)
        bitmap_shm[((cur_id ^ last_id) % MAP_SIZE)]++;
    else
        bitmap[((cur_id ^ last_id) % MAP_SIZE)]++;
    last_id = cur_id;


    if(exit_addr && exit_addr == cur_id)
        fuzzer_synchronization( (char *) "e" );
}

//  Analysis functions ----------------------------------------------------

VOID bb_instrument(TRACE trace, VOID *v)
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
                    if (1 /*INS_HasFallThrough(ins) || INS_IsCall(ins)*/)
                    {
                        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)TrackBranch,
                            IARG_INST_PTR,
                            IARG_END);
                    }
                }
            }
        }
    }
}


VOID img_instrument(IMG img, VOID *v)
{
    if(f)
        fprintf( f, "[*] module %s " HEX_FMT " " HEX_FMT "\n", IMG_Name(img).c_str(), IMG_LowAddress(img), IMG_HighAddress(img) );
    if(cover_module != "" && strcasestr( IMG_Name(img).c_str(), cover_module.c_str() ) )
    {
        if(f)
            fprintf( f, "[+] module instrumented: " HEX_FMT " " HEX_FMT " %s\n", IMG_LowAddress(img), IMG_HighAddress(img), IMG_Name(img).c_str() );
        min_addr = IMG_LowAddress(img);
        max_addr = IMG_HighAddress(img);
    }
    if(f)
        fflush(f);
}

// Main functions ------------------------------------------------

INT32 Usage()
{
    std::cerr << "AFLPIN -- A pin tool to enable blackbox binaries to be fuzzed with AFL on Linux/Windows" << std::endl;
    std::cerr << "   -debug --  prints extra debug information." << std::endl;
    std::cerr << "   -module modulename --  prints extra debug information." << std::endl;
    std::cerr << "   -exit 0xADDR --  stop address for coverage signal." << std::endl;
    return -1;
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
}
#elif __linux__
bool write_to_pipe(char *cmd)
{
    //if( access("afl_sync", F_OK ) == -1 )
    //    mkfifo("afl_sync", 777);
    if(afl_sync_fd == -1)
        afl_sync_fd = open(getenv("PIPE_SYNC"), O_WRONLY);
    write(afl_sync_fd, cmd, 1);
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
        std::cout << "shm_key: " << shm_key << std::endl;        
	
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

#ifdef __win__
void context_change(THREADID tid, CONTEXT_CHANGE_REASON reason, const CONTEXT *ctxtFrom, CONTEXT *ctxtTo, INT32 info, VOID *v)
{
    if(reason == CONTEXT_CHANGE_REASON_EXCEPTION)
    {
        printf("exception 0x%08x\n", info);
        if(info == 0xc0000005)
            windows::write_to_pipe("c");
    }
}
#elif __linux__
bool on_crash(unsigned int threadId, int sig, CONTEXT* ctx, bool hasHandler, const EXCEPTION_INFO* pExceptInfo, void* v)
{
  write_to_pipe( (char *) "c" );
  return true;
}
#endif


int main(int argc, char *argv[])
{
    if(PIN_Init(argc, argv)){
        return Usage();
    }

    #ifdef __win__
    windows::setup_shm();
    #elif __linux__
    setup_shm();
    #endif

    exit_addr = Knob_exit.Value();
    cover_module = Knob_module.Value();
    debug_file = Knob_debugfile.Value();
    if(debug_file != "")
        f = fopen(debug_file.c_str(), "w");

    PIN_SetSyntaxIntel();
    IMG_AddInstrumentFunction(img_instrument, 0);
    TRACE_AddInstrumentFunction(bb_instrument, 0);

    #ifdef __win__
    PIN_AddContextChangeFunction(context_change, 0);
    #elif __linux__
    PIN_InterceptSignal(SIGSEGV, on_crash, 0);
    #endif
    PIN_StartProgram();

    // AFL_NO_FORKSRV=1
    // We could use this main function to talk to the fork server's fd and then enable the fork server with this tool...
}

/*
For fuzzing in attach mode, with manual instrumentation.
__AFL_SHM_ID=$((0x1337)) PIPE_SYNC=/opt/afl/afl_sync pin -t /path/to/this/afl/obj-intel64/cover.so -- /usr/bin/daemon
__AFL_SHM_ID=$((0x1337)) AFL_NO_FORKSRV=1 AFL_SKIP_BIN_CHECK=1 ./afl-fuzz -i in -o out -N -T 'daemon' -- python wrap.py 127.0.0.1 1234
*/