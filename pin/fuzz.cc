#include "pin.h"
#include <stdio.h>
#include <list>
#include "exceptions.h"

CONTEXT snapshot;
BOOL is_saved_snapshot = FALSE;
BOOL in_fuzz_area = FALSE;
unsigned int fuzz_iters = 10;
struct memoryInput
{
  ADDRINT addr;
  UINT32  val;
};
list<struct memoryInput> memInput;
FILE * f;

KNOB<ADDRINT> KnobStart(KNOB_MODE_WRITEONCE, "pintool", "start", "0", "The start address of the fuzzing area");
KNOB<ADDRINT> KnobEnd(KNOB_MODE_WRITEONCE, "pintool", "end", "0", "The end address of the fuzzing area");

void randomizeREG(CONTEXT * ctx, ADDRINT nextAddr)
{
	PIN_SetContextReg(ctx, REG_EDX, fuzz_iters);
}

void restore_memory(void)
{
  list<struct memoryInput>::iterator i;

  for(i = memInput.begin(); i != memInput.end(); ++i)
  {
    *(reinterpret_cast<ADDRINT*>(i->addr)) = i->val;
    printf("restore 0x%08x <- 0x%08X\n", i->addr, i->val);
  }
  memInput.clear();
}

void write_mem(ADDRINT addr, ADDRINT memop)
{
  struct memoryInput elem;

  if(! in_fuzz_area)
  	return;
  printf("memory write\n");
  elem.addr = memop;
  elem.val = *(reinterpret_cast<ADDRINT*>(memop));
  memInput.push_back(elem);
}

void do_instrument(ADDRINT addr, ADDRINT nextAddr, CONTEXT * ctx)
{
	if( addr >= 0x401000 && addr <= 0x401024 )
		printf("0x%08x: EDX=0x%08X\n", addr, PIN_GetContextReg(ctx, REG_EDX) );

	if( addr == KnobStart.Value() && in_fuzz_area == FALSE )
	{
		in_fuzz_area = TRUE;
		PIN_SaveContext(ctx, &snapshot);
		is_saved_snapshot = TRUE;
		printf("fuzz iteration %d\n", --fuzz_iters);
		randomizeREG(ctx, nextAddr);
    	PIN_ExecuteAt(ctx);
	}
	else if( addr == KnobEnd.Value() && is_saved_snapshot )
	{
		in_fuzz_area = FALSE;
		if(fuzz_iters == 0)
			return;

		PIN_SaveContext(&snapshot, ctx);
		restore_memory();
		PIN_ExecuteAt(ctx);
	}
}

void ins_instrument(INS ins, VOID * v)
{
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)do_instrument,
					IARG_ADDRINT, INS_Address(ins),
					IARG_ADDRINT, INS_NextAddress(ins),
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



void fini(INT32 code, VOID *v)
{
	printf("end\n");
	fflush(f);
	fclose(f);
}

int main(int argc, char ** argv)
{
	f = fopen("fuzz.log", "w");
	PIN_Init(argc, argv);
	INS_AddInstrumentFunction(ins_instrument, 0);
	PIN_AddContextChangeFunction(context_change, 0);
	PIN_AddInternalExceptionHandler(internal_exception, 0);
	PIN_AddFiniFunction(fini, 0);
	printf("version 0.11\n");
	PIN_StartProgram();
	return 0;
}