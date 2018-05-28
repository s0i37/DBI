#include <pin.H>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>

#define VERSION "0.28"

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
const char *need_module;

KNOB<BOOL> Knob_debug(KNOB_MODE_WRITEONCE,  "pintool", "debug", "0", "Enable debug mode");
KNOB<string> Knob_outfile(KNOB_MODE_WRITEONCE,  "pintool", "outfile", "trace.txt", "Output file");
KNOB<ADDRINT> Knob_from(KNOB_MODE_WRITEONCE, "pintool", "from", "0", "start address (absolute) for tracing");
KNOB<ADDRINT> Knob_to(KNOB_MODE_WRITEONCE, "pintool", "to", "0", "stop address (absolute) for tracing");
KNOB<string> Knob_module(KNOB_MODE_WRITEONCE,  "pintool", "module", "", "tracing just this module");

VOID dotrace(CONTEXT *ctx, UINT32 threadid, ADDRINT eip, USIZE opcode_size)
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
	
	fprintf(f, HEX_FMT ":%x {", eip, threadid);
	for(i = 0; i < opcode_size; i++)
		fprintf(f, "%02X", ( (unsigned char *) eip )[i] );
	fprintf(f, "} " HEX_FMT "," HEX_FMT "," HEX_FMT "," HEX_FMT "," HEX_FMT "," HEX_FMT "," HEX_FMT "," HEX_FMT "\n", eax,ecx,edx,ebx,esp,ebp,esi,edi);
	fflush(f);
}


VOID do_malloc(CONTEXT * ctx, ADDRINT addr)
{
	ADDRINT esp = PIN_GetContextReg(ctx, REG_STACK_PTR);
	ADDRINT size = ( (ADDRINT *)esp )[3];
	fprintf(f, "alloc(" INT_FMT "): " HEX_FMT "\n", size, addr);
	fflush(f);
}

VOID do_free(ADDRINT addr)
{
	fprintf(f, "free(" HEX_FMT ")\n", addr);
	fflush(f);
}

VOID do_zwterminateprocess(void)
{
	fflush(f);
	fclose(f);
}


VOID ins_instrument(INS ins, VOID *v)
{
    if( INS_Address(ins) >= low_boundary && INS_Address(ins) <= high_boundary )
    //if( low_boundary && high_boundary && INS_Address(ins) >= low_boundary && INS_Address(ins) <= high_boundary )
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)dotrace, IARG_CONTEXT, IARG_UINT32, PIN_ThreadId(), IARG_INST_PTR, IARG_UINT32, INS_Size(ins), IARG_END);
}

VOID img_instrument(IMG img, VOID *v)
{
	fprintf( f, "[*] module " HEX_FMT " " HEX_FMT " %s\n", IMG_LowAddress(img), IMG_HighAddress(img), IMG_Name(img).c_str() );
	if(need_module && strcasestr( IMG_Name(img).c_str(), need_module ) )
	{
		fprintf( f, "[+] module instrumented: " HEX_FMT " " HEX_FMT " %s\n", IMG_LowAddress(img), IMG_HighAddress(img), IMG_Name(img).c_str() );
		low_boundary = IMG_LowAddress(img);
		high_boundary = IMG_HighAddress(img);
	}
	/*
	if( strstr( IMG_Name(img).c_str(), "ntdll.dll" ) )
	{
		RTN allocate_heap = RTN_FindByName(img, "RtlAllocateHeap");
		if( allocate_heap.is_valid() )
		{
			RTN_Open( allocate_heap );
			RTN_InsertCall(allocate_heap, IPOINT_AFTER, (AFUNPTR)do_malloc, IARG_CONTEXT, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END );
			RTN_Close( allocate_heap );
		}
		RTN free_heap = RTN_FindByName(img, "RtlFreeHeap");
		if( free_heap.is_valid() )
		{
			RTN_Open( free_heap );
			RTN_InsertCall( free_heap, IPOINT_BEFORE, (AFUNPTR)do_free, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_END );
			RTN_Close( free_heap );
		}
		RTN terminate_process = RTN_FindByName(img, "ZwTerminateProcess");
		if( terminate_process.is_valid() )
		{
			RTN_Open( terminate_process );
			RTN_InsertCall( terminate_process, IPOINT_BEFORE, (AFUNPTR)do_zwterminateprocess, IARG_END );
			RTN_Close( terminate_process );
		}
	}
	*/
	fflush(f);
}

VOID fini(INT32 code, VOID *v)
{
	fflush(f);
	fclose(f);
}

int main(int argc, char ** argv)
{	
	const char *outfile_name;
	if( PIN_Init(argc, argv) )
		return -1;
	
	low_boundary = Knob_from.Value();
    high_boundary = Knob_to.Value();
    need_module = Knob_module.Value().c_str();
	outfile_name = Knob_outfile.Value().c_str();
	f = fopen(outfile_name, "w");

	PIN_InitSymbols();
	IMG_AddInstrumentFunction(img_instrument, 0);
	INS_AddInstrumentFunction(ins_instrument, 0);
	PIN_AddFiniFunction(fini, 0);
	PIN_StartProgram();
	return 0;
}