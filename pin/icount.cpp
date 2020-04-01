#include <iostream>
#include "pin.H"
#include <stdio.h>
#include <stdlib.h>

#define VERSION "0.10"
#define STEP 1 * 1000 * 1000;

long unsigned int icount = 0;
unsigned int max_instructions = 0;
unsigned int edge = STEP;
const char * outfile_name;
FILE *f;

using namespace std;

KNOB<string> Knob_outfile(KNOB_MODE_WRITEONCE,  "pintool", "outfile", "icount.log", "Output file");
KNOB<ADDRINT> Knob_max_inst(KNOB_MODE_WRITEONCE, "pintool", "max_inst", "0", "maximum count of instructions for tracing");

VOID docount(INT32 c)
{
    icount += c;
    if(icount >= edge)
    {
        fprintf(f,"%lu\n",icount);
        fflush(f);
        edge += STEP;
    }
    if(icount >= max_instructions)
        PIN_Detach();
}

VOID Trace(TRACE trace, VOID *v)
{
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        INS_InsertCall(BBL_InsHead(bbl), IPOINT_BEFORE, (AFUNPTR)docount, IARG_UINT32, BBL_NumIns(bbl), IARG_END);
    }
}

VOID Fini(INT32 code, VOID *v)
{
    fclose(f);
}

int main(INT32 argc, CHAR **argv)
{
    PIN_Init(argc, argv);
    outfile_name = Knob_outfile.Value().c_str();
    max_instructions = Knob_max_inst.Value();
    f = fopen(outfile_name, "w");

    TRACE_AddInstrumentFunction(Trace, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Never returns
    PIN_StartProgram();

    return 0;
}

/*
    add r1, [m2]
        INS_Opcode(ins) = XED_ICLASS_ADD;
        INS_OperandCount(ins) = 3;
        INS_MemoryOperandCount(ins) = 1;
        INS_OperandReg(ins,0) = r1;
        INS_OperandReg(ins,1) = invalid;
        IARG_MEMORYOP_EA, 0 = m2;
        INS_MemoryOperandIsRead(ins,0) = true;
        INS_MemoryOperandIndexToOperandIndex(ins,0) = 1;
    add esp, 4
        INS_OperandCount(ins) = 3;
        INS_MemoryOperandCount(ins) = 0;;
    add [esp-10], 1
        INS_OperandCount(ins) = 3;
        INS_MemoryOperandCount(ins) = 1;
    add edi, eax
        INS_OperandCount(ins) = 3;
        INS_MemoryOperandCount(ins) = 0;
        INS_OperandReg(ins,0) = edi;
        INS_OperandReg(ins,1) = eax;
    add edx, [esi+24]
        INS_OperandCount(ins) = 3;
        INS_MemoryOperandCount(ins) = 1;
        INS_OperandReg(0) = edx;
        INS_OperandReg(1) = invalid;
    add [esi+28], eax
        INS_OperandCount(ins) = 3;
        INS_MemoryOperandCount(ins) = 1;
        INS_OperandReg(ins,0) = invalid;
        INS_OperandReg(ins,1) = eax;
    add edx, dword ptr ds:[esi+24]
        INS_RegR(ins,0) = edx;
        INS_RegR(ins,1) = esi;
        INS_RegR(ins,2) = ds;
        INS_RegR(ins,3) = invalid;
        INS_RegW(ins,0) = edx;
        INS_RegW(ins,1) = eflags;
        INS_RegW(ins,2) = invalid;
        INS_MaxNumRRegs(ins) = 3;
        INS_MaxNumWRegs(ins) = 2;
    cmp eax, 0x2733
        INS_OperandImmediate(ins,1) = 0x2733;
        INS_OperandReg(ins,2) = eflags;
        INS_OperandIsImplicit(ins,2) = true;
*/