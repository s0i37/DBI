#include <pin.H>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <list>

using namespace std;
#define VERSION "0.37"

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
unsigned int instructions = 0;
unsigned int max_instructions = 0;
int near_bytes = 0;
long long int lines = 0;

KNOB<BOOL> Knob_debug(KNOB_MODE_WRITEONCE,  "pintool", "debug", "0", "Enable debug mode");
KNOB<string> Knob_outfile(KNOB_MODE_WRITEONCE,  "pintool", "outfile", "trace.log", "Output file");
KNOB<ADDRINT> Knob_from(KNOB_MODE_WRITEONCE, "pintool", "from", "0", "start address (absolute) for tracing");
KNOB<ADDRINT> Knob_to(KNOB_MODE_WRITEONCE, "pintool", "to", "0", "stop address (absolute) for tracing");
KNOB<ADDRINT> Knob_max_inst(KNOB_MODE_WRITEONCE, "pintool", "max_inst", "0", "maximum count of instructions for tracing");
KNOB<INT32> Knob_near_bytes(KNOB_MODE_WRITEONCE, "pintool", "near_bytes", "0", "show bytes near from memory access");
KNOB<string> Knob_module(KNOB_MODE_WRITEONCE,  "pintool", "module", "", "tracing just this module");

VOID dotrace_exec(CONTEXT *ctx, UINT32 threadid, ADDRINT eip, USIZE opcode_size)
{
	unsigned int i;
	instructions += 1;
	if(instructions == max_instructions)
		PIN_Detach();
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
	lines++;

	if(lines % 100000 == 0)
		fflush(f);
}

VOID dotrace_mem_read(UINT32 threadid, ADDRINT eip, ADDRINT memop, UINT32 size)
{
	fprintf(f, "%lli:" HEX_FMT ":0x%x [" HEX_FMT "] -> ", takt, eip, threadid, memop);
	switch(size)
	{
		case 1:
			fprintf( f, "0x%02x", *(unsigned char *)memop );
			break;
		case 2:
			fprintf( f, "0x%04x", *(unsigned short *)memop );
			break;
		case 4:
			fprintf( f, "0x%08x", *(unsigned int *)memop );
			break;
		case 8:
			fprintf( f, "0x%08x", *(unsigned int *)memop );
			fprintf( f, "%08x", *( ((unsigned int *)memop) + 1 ) );
			break;
		case 16:
			fprintf( f, "0x%08x", *(unsigned int *)memop );
			fprintf( f, "%08x", *( ((unsigned int *)memop) + 1 ) );
			fprintf( f, "%08x", *( ((unsigned int *)memop) + 2 ) );
			fprintf( f, "%08x", *( ((unsigned int *)memop) + 3 ) );
			break;
	}
	fprintf(f, "\n");
	lines++;

	if(near_bytes)
	{
		BOOL has_started = false;
		for(INT32 i = 0; i < near_bytes; i++)
		{
			if(! PIN_CheckReadAccess((VOID*)(memop-near_bytes+i)))
				continue;
			if(!has_started)
			{
				fprintf(f, "%lli:" HEX_FMT ":0x%x [" HEX_FMT "]: ", takt, eip, threadid, memop-near_bytes);
				has_started = true;
			}
			fprintf( f, "%02X", *(unsigned char *)(memop-near_bytes+i) );
		}
		for(INT32 i = 0; i < near_bytes; i++)
		{
			if(! PIN_CheckReadAccess((VOID*)(memop+i)))
				break;
			fprintf( f, "%02X", *(unsigned char *)(memop+i) );
		}
		fprintf(f, "\n");
		lines++;
	}

	if(lines % 100000 == 0)
		fflush(f);
}

VOID dotrace_mem_write(UINT32 threadid, ADDRINT eip, ADDRINT memop, UINT32 size)
{
	fprintf(f, "%lli:" HEX_FMT ":0x%x [" HEX_FMT "] <- ", takt, eip, threadid, memop);
	switch(size)
	{
		case 1:
			fprintf( f, "0x%02x", *(unsigned char *)memop );
			break;
		case 2:
			fprintf( f, "0x%04x", *(unsigned short *)memop );
			break;
		case 4:
			fprintf( f, "0x%08x", *(unsigned int *)memop );
			break;
		case 8:
			fprintf( f, "0x%08x", *(unsigned int *)memop );
			fprintf( f, "%08x", *( ((unsigned int *)memop) + 1 ) );
			break;
		case 16:
			fprintf( f, "0x%08x", *(unsigned int *)memop );
			fprintf( f, "%08x", *( ((unsigned int *)memop) + 1 ) );
			fprintf( f, "%08x", *( ((unsigned int *)memop) + 2 ) );
			fprintf( f, "%08x", *( ((unsigned int *)memop) + 3 ) );
			break;
	}
	fprintf(f, "\n");
	lines++;

	if(near_bytes)
	{
		BOOL has_started = false;
		for(INT32 i = 0; i < near_bytes; i++)
		{
			if(! PIN_CheckReadAccess((VOID*)(memop-near_bytes+i)))
				continue;
			if(!has_started)
			{
				fprintf(f, "%lli:" HEX_FMT ":0x%x [" HEX_FMT "]: ", takt, eip, threadid, memop-near_bytes);
				has_started = true;
			}
			fprintf( f, "%02X", *(unsigned char *)(memop-near_bytes+i) );
		}
		for(INT32 i = 0; i < near_bytes; i++)
		{
			if(! PIN_CheckReadAccess((VOID*)(memop+i)))
				break;
			fprintf( f, "%02X", *(unsigned char *)(memop+i) );
		}
		fprintf(f, "\n");
		lines++;
	}

	if(lines % 100000 == 0)
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
	SEC sec;
	RTN rtn;
	list <string>::iterator function_name;
	fprintf( f, "[*] module %s " HEX_FMT " " HEX_FMT "\n", IMG_Name(img).c_str(), IMG_LowAddress(img), IMG_HighAddress(img) );
	if(need_module != "" && strcasestr( IMG_Name(img).c_str(), need_module.c_str() ) )
	{
		fprintf( f, "[+] module instrumented: " HEX_FMT " " HEX_FMT " %s\n", IMG_LowAddress(img), IMG_HighAddress(img), IMG_Name(img).c_str() );
		low_boundary = IMG_LowAddress(img);
		high_boundary = IMG_HighAddress(img);
	}
	fflush(f);

	for( sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec) )
		for( rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn) )
		{
			RTN_Open(rtn);
			fprintf(f, "[*] function %s " HEX_FMT " " HEX_FMT "\n", RTN_Name(rtn).c_str(), RTN_Address(rtn), RTN_Address(rtn) + RTN_Range(rtn) );
			RTN_Close(rtn);
		}

	/*for(function_name = functions.begin(); function_name != functions.end(); function_name++)
	{
		ptr = RTN_FindByName(img, (*function_name).c_str());
		if( ptr.is_valid() )
		{
			RTN_Open(ptr);
			fprintf(f, "[*] function %s " HEX_FMT "\n", RTN_Name(ptr).c_str(), RTN_Address(ptr) );
			RTN_Close(ptr);
		}
	}*/
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
    max_instructions = Knob_max_inst.Value();
    near_bytes = Knob_near_bytes.Value();
	outfile_name = Knob_outfile.Value().c_str();
	f = fopen(outfile_name, "w");
	fprintf(f, "[#] TAKT:EIP:THREAD_ID {OPCODE} EAX,ECX,EDX,EBX,ESP,EBP,ESI,EDI\n");
	fprintf(f, "[#] TAKT:EIP:THREAD_ID [MEMORY] -> READED_VALUE\n");
	fprintf(f, "[#] TAKT:EIP:THREAD_ID [MEMORY] <- WRITED_VALUE\n");

	PIN_InitSymbols();
	IMG_AddInstrumentFunction(img_instrument, 0);
	INS_AddInstrumentFunction(ins_instrument, 0);
	PIN_AddInternalExceptionHandler(internal_exception, 0);
	PIN_AddFiniFunction(fini, 0);
	PIN_StartProgram();
	return 0;
}

/*
TODO:
нужна обратная связь через pipe (tracectl) для отметки временных моментов (напр. перед подачей данных и после)
fprintf(f, "[*] event %s\n", event_name);

!problem:
	строки наезжают друг на друга
!problem:
	[0x09375c6c] <- 0x00000000 - старое значение INS_IsMemoryWrite нужно обрабатывать в IPOINT_AFTER
*/