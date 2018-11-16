#include <pin.H>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <list>

#define VERSION "0.33"

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
long long int takt = 0;
list <string> functions;

KNOB<BOOL> Knob_debug(KNOB_MODE_WRITEONCE,  "pintool", "debug", "0", "Enable debug mode");
KNOB<string> Knob_outfile(KNOB_MODE_WRITEONCE,  "pintool", "outfile", "trace.txt", "Output file");
KNOB<ADDRINT> Knob_from(KNOB_MODE_WRITEONCE, "pintool", "from", "0", "start address (absolute) for tracing");
KNOB<ADDRINT> Knob_to(KNOB_MODE_WRITEONCE, "pintool", "to", "0", "stop address (absolute) for tracing");
KNOB<string> Knob_module(KNOB_MODE_WRITEONCE,  "pintool", "module", "", "tracing just this module");

VOID dotrace_exec(CONTEXT *ctx, UINT32 threadid, ADDRINT eip, USIZE opcode_size)
{
	unsigned int i;
	ADDRINT eax = PIN_GetContextReg(ctx, REG_GAX);
	ADDRINT ecx = PIN_GetContextReg(ctx, REG_GCX);
	ADDRINT edx = PIN_GetContextReg(ctx, REG_GDX);
	ADDRINT ebx = PIN_GetContextReg(ctx, REG_GBX);
	ADDRINT esp = PIN_GetContextReg(ctx, REG_STACK_PTR);
	ADDRINT ebp = PIN_GetContextReg(ctx, REG_GBP);
	ADDRINT esi = PIN_GetContextReg(ctx, REG_GSI);
	ADDRINT edi = PIN_GetContextReg(ctx, REG_GDI);
	
	takt += 1;
	fprintf(f, "%lli:" HEX_FMT ":0x%x {", takt, eip, threadid);
	for(i = 0; i < opcode_size; i++)
		fprintf( f, "%02X", ( (unsigned char *) eip )[i] );
	fprintf(f, "} " HEX_FMT "," HEX_FMT "," HEX_FMT "," HEX_FMT "," HEX_FMT "," HEX_FMT "," HEX_FMT "," HEX_FMT "\n", eax,ecx,edx,ebx,esp,ebp,esi,edi);
	fflush(f);
}

VOID dotrace_mem_read(UINT32 threadid, ADDRINT eip, ADDRINT memop, UINT32 size)
{
	fprintf(f, "%lli:" HEX_FMT ":0x%x [" HEX_FMT "] -> ", takt, eip, threadid, memop);
	switch(size)
	{
		case 1:
			fprintf( f, "0x%02x\n", *(unsigned char *)memop );
			break;
		case 2:
			fprintf( f, "0x%04x\n", *(unsigned short *)memop );
			break;
		case 4:
			fprintf( f, "0x%08x\n", *(unsigned int *)memop );
			break;
		case 8:
			fprintf( f, "0x%08x", *(unsigned int *)memop );
			fprintf( f, "%08x\n", *( ((unsigned int *)memop) + 1 ) );
			break;

	}
	fflush(f);
}

VOID dotrace_mem_write(UINT32 threadid, ADDRINT eip, ADDRINT memop, UINT32 size)
{
	fprintf(f, "%lli:" HEX_FMT ":0x%x [" HEX_FMT "] <- ", takt, eip, threadid, memop);
	switch(size)
	{
		case 1:
			fprintf( f, "0x%02x\n", *(unsigned char *)memop );
			break;
		case 2:
			fprintf( f, "0x%04x\n", *(unsigned short *)memop );
			break;
		case 4:
			fprintf( f, "0x%08x\n", *(unsigned int *)memop );
			break;
		case 8:
			fprintf( f, "0x%08x", *(unsigned int *)memop );
			fprintf( f, "%08x\n", *( ((unsigned int *)memop) + 1 ) );
			break;

	}
	fflush(f);
}


VOID ins_instrument(INS ins, VOID *v)
{
    if( (low_boundary == 0 && high_boundary == 0) || (INS_Address(ins) >= low_boundary && INS_Address(ins) <= high_boundary) )
    {
    	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)dotrace_exec, IARG_CONTEXT, IARG_UINT32, PIN_ThreadId(), IARG_INST_PTR, IARG_UINT32, INS_Size(ins), IARG_END);
    	if( INS_IsMemoryRead(ins) )
    			INS_InsertCall(
    				ins,
    				IPOINT_BEFORE,
    				(AFUNPTR)dotrace_mem_read,
    				IARG_UINT32, PIN_ThreadId(),
    				IARG_INST_PTR,
    				IARG_MEMORYREAD_EA,
    				IARG_MEMORYREAD_SIZE,
    				IARG_END);
    	if( INS_HasMemoryRead2(ins) )
            	INS_InsertCall(
            		ins,
            		IPOINT_BEFORE,
            		(AFUNPTR)dotrace_mem_read,
					IARG_UINT32, PIN_ThreadId(),
    				IARG_INST_PTR,
					IARG_MEMORYREAD2_EA,
					IARG_MEMORYREAD_SIZE,
					IARG_END);
    	if( INS_IsMemoryWrite(ins) )
    			INS_InsertCall(
    				ins,
    				IPOINT_BEFORE,
    				(AFUNPTR)dotrace_mem_write,
    				IARG_UINT32, PIN_ThreadId(),
    				IARG_INST_PTR,
    				IARG_MEMORYWRITE_EA,
    				IARG_MEMORYWRITE_SIZE,
    				IARG_END);
    }
}

VOID img_instrument(IMG img, VOID *v)
{
	RTN ptr;
	list <string>::iterator function_name;
	fprintf( f, "[*] module " HEX_FMT " " HEX_FMT " %s\n", IMG_LowAddress(img), IMG_HighAddress(img), IMG_Name(img).c_str() );
	if(need_module != "" && strcasestr( IMG_Name(img).c_str(), need_module.c_str() ) )
	{
		fprintf( f, "[+] module instrumented: " HEX_FMT " " HEX_FMT " %s\n", IMG_LowAddress(img), IMG_HighAddress(img), IMG_Name(img).c_str() );
		low_boundary = IMG_LowAddress(img);
		high_boundary = IMG_HighAddress(img);
	}
	fflush(f);

	for(function_name = functions.begin(); function_name != functions.end(); function_name++)
	{
		ptr = RTN_FindByName(img, (*function_name).c_str());
		if( ptr.is_valid() )
		{
			RTN_Open(ptr);
			fprintf(f, "[*] function %s " HEX_FMT "\n", RTN_Name(ptr).c_str(), RTN_Address(ptr) );
			RTN_Close(ptr);
		}
	}
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
	
	functions.push_back("malloc");
	functions.push_back("free");

	low_boundary = Knob_from.Value();
    high_boundary = Knob_to.Value();
    need_module = Knob_module.Value();
	outfile_name = Knob_outfile.Value().c_str();
	f = fopen(outfile_name, "w");
	fprintf(f, "TAKT:EIP:THREAD_ID {OPCODE} EAX,ECX,EDX,EBX,ESP,EBP,ESI,EDI\n");
	fprintf(f, "TAKT:EIP:THREAD_ID [MEMORY] -> READED_VALUE\n");
	fprintf(f, "TAKT:EIP:THREAD_ID [MEMORY] <- WRITED_VALUE\n");

	PIN_InitSymbols();
	IMG_AddInstrumentFunction(img_instrument, 0);
	INS_AddInstrumentFunction(ins_instrument, 0);
	PIN_AddInternalExceptionHandler(internal_exception, 0);
	PIN_AddFiniFunction(fini, 0);
	PIN_StartProgram();
	return 0;
}