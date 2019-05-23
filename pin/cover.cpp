#include <pin.H>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <list>

#define VERSION "0.38"

#if defined(__i386__) || defined(_WIN32)
    #define HEX_FMT "0x%08x"
    #define INT_FMT "%u"
#elif defined(__x86_64__) || defined(_WIN64)
    #define HEX_FMT "0x%08lx"
    #define INT_FMT "%lu"
#endif

FILE *f;
ADDRINT low_boundary;
ADDRINT high_boundary;
string need_module;
unsigned int bb_executed = 0;
unsigned int max_bb_executed = 0;
list <string> functions;
unsigned int instructions = 0;
unsigned int max_instructions = 0;

KNOB<string> Knob_outfile(KNOB_MODE_WRITEONCE,  "pintool", "outfile", "cover.log", "Output file");
KNOB<string> Knob_module(KNOB_MODE_WRITEONCE,  "pintool", "module", "", "tracing just this module");
KNOB<unsigned int> Knob_max_bb(KNOB_MODE_WRITEONCE, "pintool", "max_bb", "0", "maximum count of basic blocks");

VOID do_trace(ADDRINT eip)
{
    fprintf(f, HEX_FMT "\n", eip-low_boundary);
    fflush(f);
    bb_executed++;
    if(bb_executed == max_bb_executed)
        PIN_Detach();
}

VOID trace_instrument(TRACE trace, VOID *v)
{
    // Instrument only at the head of the trace
    BBL bbl = TRACE_BblHead(trace);
    INS ins = BBL_InsHead(bbl);

    if( (low_boundary == 0 && high_boundary == 0) || (INS_Address(ins) >= low_boundary && INS_Address(ins) <= high_boundary) )
        if (BBL_Valid(bbl))
            INS_InsertCall(BBL_InsHead(bbl), IPOINT_BEFORE, (AFUNPTR)do_trace, IARG_INST_PTR, IARG_END);
}


VOID img_instrument(IMG img, VOID *v)
{
    fprintf( f, "[*] module %s " HEX_FMT " " HEX_FMT "\n", IMG_Name(img).c_str(), IMG_LowAddress(img), IMG_HighAddress(img) );
    if(need_module != "" && strcasestr( IMG_Name(img).c_str(), need_module.c_str() ) )
    {
        fprintf( f, "[+] module instrumented: " HEX_FMT " " HEX_FMT " %s\n", IMG_LowAddress(img), IMG_HighAddress(img), IMG_Name(img).c_str() );
        low_boundary = IMG_LowAddress(img);
        high_boundary = IMG_HighAddress(img);
    }
    fflush(f);
}

VOID fini(INT32 code, VOID *v)
{
    fflush(f);
    fclose(f);
}

EXCEPT_HANDLING_RESULT internal_exception(THREADID tid, EXCEPTION_INFO *pExceptInfo, PHYSICAL_CONTEXT *pPhysCtxt, VOID *v)
{
  //fprintf( f, "! " HEX_FMT "\n", PIN_GetPhysicalContextReg(pPhysCtxt, REG_INST_PTR) );
  fprintf(f, "!\n");
  fflush(f);
  return EHR_UNHANDLED;
}

int main(int argc, char ** argv)
{   
    const char *outfile_name;
    if( PIN_Init(argc, argv) )
        return -1;

    need_module = Knob_module.Value();
    outfile_name = Knob_outfile.Value().c_str();
    max_bb_executed = Knob_max_bb.Value();
    f = fopen(outfile_name, "w");

    IMG_AddInstrumentFunction(img_instrument, 0);
    TRACE_AddInstrumentFunction(trace_instrument, 0);
    PIN_AddInternalExceptionHandler(internal_exception, 0);
    PIN_AddFiniFunction(fini, 0);
    PIN_StartProgram();
    return 0;
}
