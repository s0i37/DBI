#include <pin.H>
#include "z3++.h"
#include <stdio.h>
#include <list>
#include <map>
#include <sstream>

using namespace std;

#define VERSION "0.26"
#define MAX_TAINT_DATA 0x1000

#if defined(__i386__) || defined(_WIN32)
	#define HEX_FMT "0x%08x"
	#define HEX_FMT2 "%08X"
	#define INT_FMT "%u"
	#define X32 1
#elif defined(__x86_64__) || defined(_WIN64)
	#define HEX_FMT "0x%08lx"
	#define HEX_FMT2 "%08lX"
	#define INT_FMT "%lu"
	#define X64 1
#endif

typedef struct {
	const char *module;
	ADDRINT low;
	ADDRINT high;
} MODULE;

typedef struct {
	UINT64 rax;
	UINT64 rcx;
	UINT64 rdx;
	UINT64 rbx;
	UINT64 rbp;
	UINT64 rsp;
	UINT64 rsi;
	UINT64 rdi;
} Registers;

typedef struct {
	UINT64 value;
	UINT32 size;
	BOOL is_tainted;
	ADDRINT source;
} Operand;

typedef struct {
	Operand operand1;
	Operand operand2;
	Registers registers;
} Operands;

list <ADDRINT> pages;
list <MODULE> modules;
list <ADDRINT> tainted_addrs;
map <ADDRINT, unsigned int> tainted_offsets;
map <ADDRINT, unsigned int> tainted_operations;
map < int, list <REG> > tainted_regs;
enum MemoryOperand {
	READ = 0b01,
	WRITE = 0b10,
	READ_WRITE = 0b11
};
map < int, Operands > operands;
map < int, string > equations;
map < int, string > symbolic_memory;
map < int, map<int,string> > symbolic_registers;

z3::context   *z3Context;
z3::expr      *z3Var;
z3::solver    *z3Solver;
z3::expr      *z3Equation;
z3::model     *z3Model;

string need_module;
ADDRINT low_boundary;
ADDRINT high_boundary;
FILE *f, *taint_data_file;
unsigned char *taint_data;
UINT32 taint_data_len;
UINT32 taint_offset;
UINT32 taint_size;

unsigned long int ins_count = 0;

KNOB<BOOL> Knob_debug(KNOB_MODE_WRITEONCE,  "pintool", "debug", "0", "Enable debug mode");
KNOB<string> Knob_outfile(KNOB_MODE_WRITEONCE,  "pintool", "outfile", "concolic.log", "Output file");
KNOB<ADDRINT> Knob_from(KNOB_MODE_WRITEONCE, "pintool", "from", "0", "start address (absolute) for taint");
KNOB<ADDRINT> Knob_to(KNOB_MODE_WRITEONCE, "pintool", "to", "0", "stop address (absolute) for taint");
KNOB<string> Knob_module(KNOB_MODE_WRITEONCE,  "pintool", "module", "", "taint this module");
KNOB<string> Knob_taint(KNOB_MODE_WRITEONCE,  "pintool", "taint", "", "taint this data");
KNOB<UINT32> Knob_offset(KNOB_MODE_WRITEONCE,  "pintool", "offset", "0", "from offset (subdata)");
KNOB<UINT32> Knob_size(KNOB_MODE_WRITEONCE,  "pintool", "size", "0", "size bytes (subdata)");

void add_symbolic_memory(ADDRINT addr, string expression)
{
	fprintf(f,"[debug] 0x%lx: %s\n", addr, expression.c_str());
	symbolic_memory[addr] = expression;
}
void add_symbolic_register(REG reg, UINT32 threadid, string expression)
{
	fprintf(f,"[debug] %s= %s\n", REG_StringShort(reg).c_str(), expression.c_str());
	switch(reg)
	{
		case REG_AH:	symbolic_registers[threadid][REG_AH] = expression;
						return;
		case REG_DH:	symbolic_registers[threadid][REG_DH] = expression;
						return;
		case REG_CH:	symbolic_registers[threadid][REG_CH] = expression;
						return;
		case REG_BH:	symbolic_registers[threadid][REG_BH] = expression;
						return;
		default:		break;
	}

	switch(reg)
	{
		case REG_GAX:	symbolic_registers[threadid][REG_GAX] = expression;
	#if defined(X64)
		case REG_EAX:	symbolic_registers[threadid][REG_EAX] = expression;
	#endif
		case REG_AX:	symbolic_registers[threadid][REG_AX] = expression;
		case REG_AH:	symbolic_registers[threadid][REG_AH] = expression;
		case REG_AL:	symbolic_registers[threadid][REG_AL] = expression;
						break;

		case REG_GDX:	symbolic_registers[threadid][REG_GDX] = expression;
	#if defined(X64)
		case REG_EDX:	symbolic_registers[threadid][REG_EDX] = expression;
	#endif
		case REG_DX:	symbolic_registers[threadid][REG_DX] = expression;
		case REG_DH:	symbolic_registers[threadid][REG_DH] = expression;
		case REG_DL:	symbolic_registers[threadid][REG_DL] = expression;
						break;

		case REG_GCX:	symbolic_registers[threadid][REG_GCX] = expression;
	#if defined(X64)
		case REG_ECX:	symbolic_registers[threadid][REG_ECX] = expression;
	#endif
		case REG_CX:	symbolic_registers[threadid][REG_CX] = expression;
		case REG_CH:	symbolic_registers[threadid][REG_CH] = expression;
		case REG_CL:	symbolic_registers[threadid][REG_CL] = expression;
						break;

		case REG_GBX:	symbolic_registers[threadid][REG_GBX] = expression;
	#if defined(X64)
		case REG_EBX:	symbolic_registers[threadid][REG_EBX] = expression;
	#endif
		case REG_BX:	symbolic_registers[threadid][REG_BX] = expression;
		case REG_BH:	symbolic_registers[threadid][REG_BH] = expression;
		case REG_BL:	symbolic_registers[threadid][REG_BL] = expression;
						break;

		case REG_GBP: 	symbolic_registers[threadid][REG_GBP] = expression;
	#if defined(X64)
		case REG_EBP: 	symbolic_registers[threadid][REG_EBP] = expression;
	#endif
		case REG_BP: 	symbolic_registers[threadid][REG_BP] = expression;
						break;

		case REG_GDI:	symbolic_registers[threadid][REG_GDI] = expression;
	#if defined(X64)
		case REG_EDI:	symbolic_registers[threadid][REG_EDI] = expression;
	#endif
		case REG_DI:	symbolic_registers[threadid][REG_DI] = expression;
						break;

		case REG_GSI:	symbolic_registers[threadid][REG_GSI] = expression;
	#if defined(X64)
		case REG_ESI:	symbolic_registers[threadid][REG_ESI] = expression;
	#endif
		case REG_SI:	symbolic_registers[threadid][REG_SI] = expression;
						break;

	#if defined(X64)
		case REG_R8: 	symbolic_registers[threadid][REG_R8] = expression;
		case REG_R8D:	symbolic_registers[threadid][REG_R8D] = expression;
		case REG_R8W:	symbolic_registers[threadid][REG_R8W] = expression;
		case REG_R8B:	symbolic_registers[threadid][REG_R8B] = expression;
						break;
	#endif

	#if defined(X64)
		case REG_R9: 	symbolic_registers[threadid][REG_R9] = expression;
		case REG_R9D:	symbolic_registers[threadid][REG_R9D] = expression;
		case REG_R9W:	symbolic_registers[threadid][REG_R9W] = expression;
		case REG_R9B:	symbolic_registers[threadid][REG_R9B] = expression;
						break;
	#endif

	#if defined(X64)
		case REG_R10: 	symbolic_registers[threadid][REG_R10] = expression;
		case REG_R10D:	symbolic_registers[threadid][REG_R10D] = expression;
		case REG_R10W:	symbolic_registers[threadid][REG_R10W] = expression;
		case REG_R10B:	symbolic_registers[threadid][REG_R10B] = expression;
						break;
	#endif

	#if defined(X64)
		case REG_R11: 	symbolic_registers[threadid][REG_R11] = expression;
		case REG_R11D:	symbolic_registers[threadid][REG_R11D] = expression;
		case REG_R11W:	symbolic_registers[threadid][REG_R11W] = expression;
		case REG_R11B:	symbolic_registers[threadid][REG_R11B] = expression;
						break;
	#endif

	#if defined(X64)
		case REG_R12: 	symbolic_registers[threadid][REG_R12] = expression;
		case REG_R12D:	symbolic_registers[threadid][REG_R12D] = expression;
		case REG_R12W:	symbolic_registers[threadid][REG_R12W] = expression;
		case REG_R12B:	symbolic_registers[threadid][REG_R12B] = expression;
						break;
	#endif

	#if defined(X64)
		case REG_R13: 	symbolic_registers[threadid][REG_R13] = expression;
		case REG_R13D:	symbolic_registers[threadid][REG_R13D] = expression;
		case REG_R13W:	symbolic_registers[threadid][REG_R13W] = expression;
		case REG_R13B:	symbolic_registers[threadid][REG_R13B] = expression;
						break;
	#endif

	#if defined(X64)
		case REG_R14: 	symbolic_registers[threadid][REG_R14] = expression;
		case REG_R14D:	symbolic_registers[threadid][REG_R14D] = expression;
		case REG_R14W:	symbolic_registers[threadid][REG_R14W] = expression;
		case REG_R14B:	symbolic_registers[threadid][REG_R14B] = expression;
						break;
	#endif

	#if defined(X64)
		case REG_R15: 	symbolic_registers[threadid][REG_R15] = expression;
		case REG_R15D:	symbolic_registers[threadid][REG_R15D] = expression;
		case REG_R15W:	symbolic_registers[threadid][REG_R15W] = expression;
		case REG_R15B:	symbolic_registers[threadid][REG_R15B] = expression;
						break;
	#endif

	case REG_XMM0:	symbolic_registers[threadid][REG_XMM0] = expression;
					break;
	case REG_XMM1:	symbolic_registers[threadid][REG_XMM1] = expression;
					break;
	case REG_XMM2:	symbolic_registers[threadid][REG_XMM2] = expression;
					break;
	case REG_XMM3:	symbolic_registers[threadid][REG_XMM3] = expression;
					break;
	case REG_XMM4:	symbolic_registers[threadid][REG_XMM4] = expression;
					break;
	case REG_XMM5:	symbolic_registers[threadid][REG_XMM5] = expression;
					break;
	case REG_XMM6:	symbolic_registers[threadid][REG_XMM6] = expression;
					break;
	case REG_XMM7:	symbolic_registers[threadid][REG_XMM7] = expression;
					break;
	#if defined(X64)
	case REG_XMM8:	symbolic_registers[threadid][REG_XMM8] = expression;
					break;
	case REG_XMM9:	symbolic_registers[threadid][REG_XMM9] = expression;
					break;
	case REG_XMM10:	symbolic_registers[threadid][REG_XMM10] = expression;
					break;
	case REG_XMM11:	symbolic_registers[threadid][REG_XMM11] = expression;
					break;
	case REG_XMM12:	symbolic_registers[threadid][REG_XMM12] = expression;
					break;
	case REG_XMM13:	symbolic_registers[threadid][REG_XMM13] = expression;
					break;
	case REG_XMM14:	symbolic_registers[threadid][REG_XMM14] = expression;
					break;
	case REG_XMM15:	symbolic_registers[threadid][REG_XMM15] = expression;
					break;
	#endif

	case REG_ST0:	symbolic_registers[threadid][REG_ST0] = expression;
					break;
	case REG_ST1:	symbolic_registers[threadid][REG_ST1] = expression;
					break;
	case REG_ST2:	symbolic_registers[threadid][REG_ST2] = expression;
					break;
	case REG_ST3:	symbolic_registers[threadid][REG_ST3] = expression;
					break;
	case REG_ST4:	symbolic_registers[threadid][REG_ST4] = expression;
					break;
	case REG_ST5:	symbolic_registers[threadid][REG_ST5] = expression;
					break;
	case REG_ST6:	symbolic_registers[threadid][REG_ST6] = expression;
					break;
	case REG_ST7:	symbolic_registers[threadid][REG_ST7] = expression;
					break;

	#if defined(X64)
		case REG_RFLAGS:	symbolic_registers[threadid][REG_RFLAGS] = expression;
	#endif
	case REG_EFLAGS:	symbolic_registers[threadid][REG_EFLAGS] = expression;
	case REG_FLAGS:		symbolic_registers[threadid][REG_FLAGS] = expression;
						break;
	default:		break;
	}
}
void del_symbolic_memory(ADDRINT addr)
{	
	symbolic_memory[addr] = "";
}
void del_symbolic_register(REG reg, UINT32 threadid)
{
	symbolic_registers[threadid][reg] = "";
}

void add_mem_taint(ADDRINT addr)
{
	tainted_addrs.push_back(addr);
}
void del_mem_taint(ADDRINT addr)
{
	tainted_addrs.remove(addr);
}
void save_page(ADDRINT addr)
{
	list <ADDRINT>::iterator it;
	addr = addr >> 12;
	addr = addr << 12;
	for( it = pages.begin(); it != pages.end(); it++ )
		if( addr == *it )
			return;
	pages.push_back(addr);
}


bool check_reg_taint(REG reg, UINT32 threadid)
{
	list<REG>::iterator it;
	if( tainted_regs.count(threadid) == 0 )
		return FALSE;
	for( it = tainted_regs[threadid].begin(); it != tainted_regs[threadid].end(); it++ )
		if( *it == reg )
			return TRUE;
	return FALSE;
}

bool add_reg_taint(REG reg, UINT32 threadid)
{
	if( check_reg_taint(reg, threadid) == TRUE )
		return FALSE;

	switch(reg)
	{
		case REG_AH:	tainted_regs[threadid].push_front(REG_AH);
						return TRUE;
		case REG_DH:	tainted_regs[threadid].push_front(REG_DH);
						return TRUE;
		case REG_CH:	tainted_regs[threadid].push_front(REG_CH);
						return TRUE;
		case REG_BH:	tainted_regs[threadid].push_front(REG_BH);
						return TRUE;
		default:		break;
	}

	switch(reg)
	{
		case REG_GAX:	tainted_regs[threadid].push_front(REG_GAX);
	#if defined(X64)
		case REG_EAX:	tainted_regs[threadid].push_front(REG_EAX);
	#endif
		case REG_AX:	tainted_regs[threadid].push_front(REG_AX);
		case REG_AH:	tainted_regs[threadid].push_front(REG_AH);
		case REG_AL:	tainted_regs[threadid].push_front(REG_AL);
						break;

		case REG_GDX:	tainted_regs[threadid].push_front(REG_GDX);
	#if defined(X64)
		case REG_EDX:	tainted_regs[threadid].push_front(REG_EDX);
	#endif
		case REG_DX:	tainted_regs[threadid].push_front(REG_DX);
		case REG_DH:	tainted_regs[threadid].push_front(REG_DH);
		case REG_DL:	tainted_regs[threadid].push_front(REG_DL);
						break;

		case REG_GCX:	tainted_regs[threadid].push_front(REG_GCX);
	#if defined(X64)
		case REG_ECX:	tainted_regs[threadid].push_front(REG_ECX);
	#endif
		case REG_CX:	tainted_regs[threadid].push_front(REG_CX);
		case REG_CH:	tainted_regs[threadid].push_front(REG_CH);
		case REG_CL:	tainted_regs[threadid].push_front(REG_CL);
						break;

		case REG_GBX:	tainted_regs[threadid].push_front(REG_GBX);
	#if defined(X64)
		case REG_EBX:	tainted_regs[threadid].push_front(REG_EBX);
	#endif
		case REG_BX:	tainted_regs[threadid].push_front(REG_BX);
		case REG_BH:	tainted_regs[threadid].push_front(REG_BH);
		case REG_BL:	tainted_regs[threadid].push_front(REG_BL);
						break;

		case REG_GBP: 	tainted_regs[threadid].push_front(REG_GBP);
	#if defined(X64)
		case REG_EBP: 	tainted_regs[threadid].push_front(REG_EBP);
	#endif
		case REG_BP: 	tainted_regs[threadid].push_front(REG_BP);
						break;

		case REG_GDI:	tainted_regs[threadid].push_front(REG_GDI);
	#if defined(X64)
		case REG_EDI:	tainted_regs[threadid].push_front(REG_EDI);
	#endif
		case REG_DI:	tainted_regs[threadid].push_front(REG_DI);
						break;

		case REG_GSI:	tainted_regs[threadid].push_front(REG_GSI);
	#if defined(X64)
		case REG_ESI:	tainted_regs[threadid].push_front(REG_ESI);
	#endif
		case REG_SI:	tainted_regs[threadid].push_front(REG_SI);
						break;

	#if defined(X64)
		case REG_R8: 	tainted_regs[threadid].push_front(REG_R8);
		case REG_R8D:	tainted_regs[threadid].push_front(REG_R8D);
		case REG_R8W:	tainted_regs[threadid].push_front(REG_R8W);
		case REG_R8B:	tainted_regs[threadid].push_front(REG_R8B);
						break;
	#endif

	#if defined(X64)
		case REG_R9: 	tainted_regs[threadid].push_front(REG_R9);
		case REG_R9D:	tainted_regs[threadid].push_front(REG_R9D);
		case REG_R9W:	tainted_regs[threadid].push_front(REG_R9W);
		case REG_R9B:	tainted_regs[threadid].push_front(REG_R9B);
						break;
	#endif

	#if defined(X64)
		case REG_R10: 	tainted_regs[threadid].push_front(REG_R10);
		case REG_R10D:	tainted_regs[threadid].push_front(REG_R10D);
		case REG_R10W:	tainted_regs[threadid].push_front(REG_R10W);
		case REG_R10B:	tainted_regs[threadid].push_front(REG_R10B);
						break;
	#endif

	#if defined(X64)
		case REG_R11: 	tainted_regs[threadid].push_front(REG_R11);
		case REG_R11D:	tainted_regs[threadid].push_front(REG_R11D);
		case REG_R11W:	tainted_regs[threadid].push_front(REG_R11W);
		case REG_R11B:	tainted_regs[threadid].push_front(REG_R11B);
						break;
	#endif

	#if defined(X64)
		case REG_R12: 	tainted_regs[threadid].push_front(REG_R12);
		case REG_R12D:	tainted_regs[threadid].push_front(REG_R12D);
		case REG_R12W:	tainted_regs[threadid].push_front(REG_R12W);
		case REG_R12B:	tainted_regs[threadid].push_front(REG_R12B);
						break;
	#endif

	#if defined(X64)
		case REG_R13: 	tainted_regs[threadid].push_front(REG_R13);
		case REG_R13D:	tainted_regs[threadid].push_front(REG_R13D);
		case REG_R13W:	tainted_regs[threadid].push_front(REG_R13W);
		case REG_R13B:	tainted_regs[threadid].push_front(REG_R13B);
						break;
	#endif

	#if defined(X64)
		case REG_R14: 	tainted_regs[threadid].push_front(REG_R14);
		case REG_R14D:	tainted_regs[threadid].push_front(REG_R14D);
		case REG_R14W:	tainted_regs[threadid].push_front(REG_R14W);
		case REG_R14B:	tainted_regs[threadid].push_front(REG_R14B);
						break;
	#endif

	#if defined(X64)
		case REG_R15: 	tainted_regs[threadid].push_front(REG_R15);
		case REG_R15D:	tainted_regs[threadid].push_front(REG_R15D);
		case REG_R15W:	tainted_regs[threadid].push_front(REG_R15W);
		case REG_R15B:	tainted_regs[threadid].push_front(REG_R15B);
						break;
	#endif

	case REG_XMM0:	tainted_regs[threadid].push_front(REG_XMM0);
					break;
	case REG_XMM1:	tainted_regs[threadid].push_front(REG_XMM1);
					break;
	case REG_XMM2:	tainted_regs[threadid].push_front(REG_XMM2);
					break;
	case REG_XMM3:	tainted_regs[threadid].push_front(REG_XMM3);
					break;
	case REG_XMM4:	tainted_regs[threadid].push_front(REG_XMM4);
					break;
	case REG_XMM5:	tainted_regs[threadid].push_front(REG_XMM5);
					break;
	case REG_XMM6:	tainted_regs[threadid].push_front(REG_XMM6);
					break;
	case REG_XMM7:	tainted_regs[threadid].push_front(REG_XMM7);
					break;
	#if defined(X64)
	case REG_XMM8:	tainted_regs[threadid].push_front(REG_XMM8);
					break;
	case REG_XMM9:	tainted_regs[threadid].push_front(REG_XMM9);
					break;
	case REG_XMM10:	tainted_regs[threadid].push_front(REG_XMM10);
					break;
	case REG_XMM11:	tainted_regs[threadid].push_front(REG_XMM11);
					break;
	case REG_XMM12:	tainted_regs[threadid].push_front(REG_XMM12);
					break;
	case REG_XMM13:	tainted_regs[threadid].push_front(REG_XMM13);
					break;
	case REG_XMM14:	tainted_regs[threadid].push_front(REG_XMM14);
					break;
	case REG_XMM15:	tainted_regs[threadid].push_front(REG_XMM15);
					break;
	#endif

	case REG_ST0:	tainted_regs[threadid].push_front(REG_ST0);
					break;
	case REG_ST1:	tainted_regs[threadid].push_front(REG_ST1);
					break;
	case REG_ST2:	tainted_regs[threadid].push_front(REG_ST2);
					break;
	case REG_ST3:	tainted_regs[threadid].push_front(REG_ST3);
					break;
	case REG_ST4:	tainted_regs[threadid].push_front(REG_ST4);
					break;
	case REG_ST5:	tainted_regs[threadid].push_front(REG_ST5);
					break;
	case REG_ST6:	tainted_regs[threadid].push_front(REG_ST6);
					break;
	case REG_ST7:	tainted_regs[threadid].push_front(REG_ST7);
					break;

	#if defined(X64)
		case REG_RFLAGS:	tainted_regs[threadid].push_front(REG_RFLAGS);
	#endif
	case REG_EFLAGS:	tainted_regs[threadid].push_front(REG_EFLAGS);
	case REG_FLAGS:		tainted_regs[threadid].push_front(REG_FLAGS);
						break;
		
		default:		
						return FALSE;
	}
	return TRUE;
}

bool del_reg_taint(REG reg, UINT32 threadid)
{
	if( check_reg_taint(reg, threadid) == FALSE )
		return FALSE;

	switch(reg)
	{
		case REG_AH:	tainted_regs[threadid].remove(REG_AH);
						return TRUE;
		case REG_DH:	tainted_regs[threadid].remove(REG_DH);
						return TRUE;
		case REG_CH:	tainted_regs[threadid].remove(REG_CH);
						return TRUE;
		case REG_BH:	tainted_regs[threadid].remove(REG_BH);
						return TRUE;
		default:		break;
	}
	
	switch(reg)
	{
		case REG_GAX:	tainted_regs[threadid].remove(REG_GAX);
	#if defined(X64)
		case REG_EAX:	tainted_regs[threadid].remove(REG_EAX);
	#endif
		case REG_AX:	tainted_regs[threadid].remove(REG_AX);
		case REG_AH:	tainted_regs[threadid].remove(REG_AH);
		case REG_AL:	tainted_regs[threadid].remove(REG_AL);
						break;

		case REG_GDX:	tainted_regs[threadid].remove(REG_GDX);
	#if defined(X64)
		case REG_EDX:	tainted_regs[threadid].remove(REG_EDX);
	#endif
		case REG_DX:	tainted_regs[threadid].remove(REG_DX);
		case REG_DH:	tainted_regs[threadid].remove(REG_DH);
		case REG_DL:	tainted_regs[threadid].remove(REG_DL);
						break;

		case REG_GCX:	tainted_regs[threadid].remove(REG_GCX);
	#if defined(X64)
		case REG_ECX:	tainted_regs[threadid].remove(REG_ECX);
	#endif
		case REG_CX:	tainted_regs[threadid].remove(REG_CX);
		case REG_CH:	tainted_regs[threadid].remove(REG_CH);
		case REG_CL:	tainted_regs[threadid].remove(REG_CL);
						break;

		case REG_GBX:	tainted_regs[threadid].remove(REG_GBX);
	#if defined(X64)
		case REG_EBX:	tainted_regs[threadid].remove(REG_EBX);
	#endif
		case REG_BX:	tainted_regs[threadid].remove(REG_BX);
		case REG_BH:	tainted_regs[threadid].remove(REG_BH);
		case REG_BL:	tainted_regs[threadid].remove(REG_BL);
						break;

		case REG_GBP:	tainted_regs[threadid].remove(REG_GBP);
	#if defined(X64)
		case REG_EBP:	tainted_regs[threadid].remove(REG_EBP);
	#endif
		case REG_BP: 	tainted_regs[threadid].remove(REG_BP);
						break;

		case REG_GDI:	tainted_regs[threadid].remove(REG_GDI);
	#if defined(X64)
		case REG_EDI:	tainted_regs[threadid].remove(REG_EDI);
	#endif
		case REG_DI:	tainted_regs[threadid].remove(REG_DI);
						break;

		case REG_GSI:	tainted_regs[threadid].remove(REG_GSI);
	#if defined(X64)
		case REG_ESI:	tainted_regs[threadid].remove(REG_ESI);
	#endif
		case REG_SI:	tainted_regs[threadid].remove(REG_SI);
						break;

	#if defined(X64)
		case REG_R8:	tainted_regs[threadid].remove(REG_R8);
		case REG_R8D:	tainted_regs[threadid].remove(REG_R8D);
		case REG_R8W:	tainted_regs[threadid].remove(REG_R8W);
		case REG_R8B:	tainted_regs[threadid].remove(REG_R8B);
						break;
	#endif

	#if defined(X64)
		case REG_R9:	tainted_regs[threadid].remove(REG_R9);
		case REG_R9D:	tainted_regs[threadid].remove(REG_R9D);
		case REG_R9W:	tainted_regs[threadid].remove(REG_R9W);
		case REG_R9B:	tainted_regs[threadid].remove(REG_R9B);
						break;
	#endif

	#if defined(X64)
		case REG_R10:	tainted_regs[threadid].remove(REG_R10);
		case REG_R10D:	tainted_regs[threadid].remove(REG_R10D);
		case REG_R10W:	tainted_regs[threadid].remove(REG_R10W);
		case REG_R10B:	tainted_regs[threadid].remove(REG_R10B);
						break;
	#endif

	#if defined(X64)
		case REG_R11:	tainted_regs[threadid].remove(REG_R11);
		case REG_R11D:	tainted_regs[threadid].remove(REG_R11D);
		case REG_R11W:	tainted_regs[threadid].remove(REG_R11W);
		case REG_R11B:	tainted_regs[threadid].remove(REG_R11B);
						break;
	#endif

	#if defined(X64)
		case REG_R12:	tainted_regs[threadid].remove(REG_R12);
		case REG_R12D:	tainted_regs[threadid].remove(REG_R12D);
		case REG_R12W:	tainted_regs[threadid].remove(REG_R12W);
		case REG_R12B:	tainted_regs[threadid].remove(REG_R12B);
						break;
	#endif

	#if defined(X64)
		case REG_R13:	tainted_regs[threadid].remove(REG_R13);
		case REG_R13D:	tainted_regs[threadid].remove(REG_R13D);
		case REG_R13W:	tainted_regs[threadid].remove(REG_R13W);
		case REG_R13B:	tainted_regs[threadid].remove(REG_R13B);
						break;
	#endif

	#if defined(X64)
		case REG_R14:	tainted_regs[threadid].remove(REG_R14);
		case REG_R14D:	tainted_regs[threadid].remove(REG_R14D);
		case REG_R14W:	tainted_regs[threadid].remove(REG_R14W);
		case REG_R14B:	tainted_regs[threadid].remove(REG_R14B);
						break;
	#endif

	#if defined(X64)
		case REG_R15:	tainted_regs[threadid].remove(REG_R15);
		case REG_R15D:	tainted_regs[threadid].remove(REG_R15D);
		case REG_R15W:	tainted_regs[threadid].remove(REG_R15W);
		case REG_R15B:	tainted_regs[threadid].remove(REG_R15B);
						break;
	#endif

	case REG_XMM0:	tainted_regs[threadid].remove(REG_XMM0);
					break;
	case REG_XMM1:	tainted_regs[threadid].remove(REG_XMM1);
					break;
	case REG_XMM2:	tainted_regs[threadid].remove(REG_XMM2);
					break;
	case REG_XMM3:	tainted_regs[threadid].remove(REG_XMM3);
					break;
	case REG_XMM4:	tainted_regs[threadid].remove(REG_XMM4);
					break;
	case REG_XMM5:	tainted_regs[threadid].remove(REG_XMM5);
					break;
	case REG_XMM6:	tainted_regs[threadid].remove(REG_XMM6);
					break;
	case REG_XMM7:	tainted_regs[threadid].remove(REG_XMM7);
					break;
	#if defined(X64)
	case REG_XMM8:	tainted_regs[threadid].remove(REG_XMM8);
					break;
	case REG_XMM9:	tainted_regs[threadid].remove(REG_XMM9);
					break;
	case REG_XMM10:	tainted_regs[threadid].remove(REG_XMM10);
					break;
	case REG_XMM11:	tainted_regs[threadid].remove(REG_XMM11);
					break;
	case REG_XMM12:	tainted_regs[threadid].remove(REG_XMM12);
					break;
	case REG_XMM13:	tainted_regs[threadid].remove(REG_XMM13);
					break;
	case REG_XMM14:	tainted_regs[threadid].remove(REG_XMM14);
					break;
	case REG_XMM15:	tainted_regs[threadid].remove(REG_XMM15);
					break;
	#endif
					
	
	case REG_ST0:	tainted_regs[threadid].remove(REG_ST0);
					break;
	case REG_ST1:	tainted_regs[threadid].remove(REG_ST1);
					break;
	case REG_ST2:	tainted_regs[threadid].remove(REG_ST2);
					break;
	case REG_ST3:	tainted_regs[threadid].remove(REG_ST3);
					break;
	case REG_ST4:	tainted_regs[threadid].remove(REG_ST4);
					break;
	case REG_ST5:	tainted_regs[threadid].remove(REG_ST5);
					break;
	case REG_ST6:	tainted_regs[threadid].remove(REG_ST6);
					break;
	case REG_ST7:	tainted_regs[threadid].remove(REG_ST7);
					break;

	#if defined(X64)
		case REG_RFLAGS:	tainted_regs[threadid].remove(REG_RFLAGS);
	#endif
	case REG_EFLAGS:	tainted_regs[threadid].remove(REG_EFLAGS);
	case REG_FLAGS:		tainted_regs[threadid].remove(REG_FLAGS);
						break;

		default:		
						return FALSE;
	}
	return TRUE;
}



void print_tainted_regs(UINT32 threadid)
{
	list<REG>::iterator it;
	if( tainted_regs.count(threadid) == 0 )
		return;
	for( it = tainted_regs[threadid].begin(); it != tainted_regs[threadid].end(); it++ )
		printf( "%s,", REG_StringShort(*it).c_str() );
	printf("\n");
}

void telescope(ADDRINT addr, UINT32 deep)
{
	if(deep >= 5)
	{
		fprintf(f, " ...;");
		return;
	}

	list <ADDRINT>::iterator it;
	for( it = pages.begin(); it != pages.end(); it++ )
		if( (addr & 0xfffff000) == *it )
		{
			fprintf(f, " -> " HEX_FMT, *((ADDRINT *)addr) );
			telescope( *((ADDRINT *)addr), deep+1 );
			return;
		}
	fprintf(f, ";");

}

const char *get_module_name(ADDRINT addr)
{
	list <MODULE>::iterator module_it;
	for( module_it = modules.begin(); module_it != modules.end(); module_it++ )
		if( module_it->low <= addr && module_it->high >= addr )
			return module_it->module;
	return "";
}

ADDRINT get_module_base(ADDRINT addr)
{
	list <MODULE>::iterator module_it;
	for( module_it = modules.begin(); module_it != modules.end(); module_it++ )
		if( module_it->low <= addr && module_it->high >= addr )
			return module_it->low;
	return 0;
}

void find_tainted_data(ADDRINT mem)
{
	unsigned int i = 0;
	BOOL is_match = false;
	list <ADDRINT>::iterator addr_it;
	char sym[8] = {0};

	if(PIN_CheckReadAccess((VOID*)mem))
		for(i = 0; i < taint_data_len; i++)
			if( taint_data[i] == *(unsigned char *)mem )
			{
				is_match = true;
				mem -= i;
				break;
			}

	if(!is_match)
		return;

	for(i = 0; i < taint_data_len; i++)
		if( PIN_CheckReadAccess((VOID*)(mem+i)) && taint_data[i] != ((unsigned char *)mem)[i] )
		{
			is_match = false;
			break;
		}

	if(!is_match)
		return;
	
	for( addr_it = tainted_addrs.begin(); addr_it != tainted_addrs.end(); addr_it++ )
		if( mem == *addr_it )
			return;

	for(i = 0; i < taint_data_len; i++)
	{
		if(i%0x10 == 0)
			fprintf(f, "\n[+] found tainted data " HEX_FMT ":\t", mem+i);
		fprintf( f, "%02X ", *(unsigned char *)(mem + i) );
		if(taint_size)
		{
			if(i >= taint_offset && i < taint_offset+taint_size)
			{
				add_mem_taint(mem + i);
				sprintf((char *)&sym, "X%d", i);
				add_symbolic_memory( mem+i, sym );
			}
		}
		else
		{
			add_mem_taint(mem + i);
			sprintf((char *)&sym, "X%d", i);
			add_symbolic_memory( mem+i, sym );
		}
		tainted_offsets[mem+i] = i;
	}
	fprintf(f, "\n");
}

void get_operands_value(UINT32 threadid, CONTEXT * ctx, UINT32 rregs_count, REG * rregs, UINT32 wregs_count, REG * wregs, UINT32 mems_count, UINT32 memop0_type, ADDRINT memop0, UINT32 memop1_type, ADDRINT memop1, UINT32 size, UINT32 memop_index, UINT64 immediate, UINT32 immediate_size)
{
	UINT8 register_value[128] = {0};
	list <ADDRINT>::iterator addr_it;
	/* 
	+	ins reg,[reg] 	mems_count==1 && rregs_count>1 && memop_index == 1
	*	ins reg,[imm] 	mems_count==1 && rregs_count==1 && memop_index == 1
	+	ins reg,reg 	mems_count==0 && rregs_count==2
	+	ins reg,imm 	mems_count==0 && immediate_size>0
	+	ins [reg],imm 	mems_count==1 && immediate_size>0 && memop_index == 0

	+	ins [reg],reg 	mems_count==1 && rregs_count>1 && memop_index == 0
	*	ins [imm],reg 	mems_count==1 && rregs_count==1 && memop_index == 0
	*/
	/* cmp byte [rax + rdx], cl */
	if( mems_count == 1 && immediate_size == 0 && memop_index == 1 ) /* ins reg, [reg/imm] */
	{
		//fprintf(f, "[debug] ins reg, [mem] %d\n", memop_index);
		PIN_GetContextRegval(ctx, rregs[0], (UINT8 *)&register_value);
		operands[threadid].operand1.size = REG_Size(rregs[0]);
		operands[threadid].operand1.source = (ADDRINT)rregs[0];
		switch( operands[threadid].operand1.size )
		{
			case 1: operands[threadid].operand1.value = (UINT64) ((UINT8 *)register_value)[0];
					break;
			case 2: operands[threadid].operand1.value = (UINT64) ((UINT16 *)register_value)[0];
					break;
			case 4: operands[threadid].operand1.value = (UINT64) ((UINT32 *)register_value)[0];
					break;
			case 8: operands[threadid].operand1.value = ((UINT64 *)register_value)[0];
					break;
		}
		if( check_reg_taint( rregs[0], threadid ) )
			operands[threadid].operand1.is_tainted = true;
		else
			operands[threadid].operand1.is_tainted = false;

		operands[threadid].operand2.size = size;
		operands[threadid].operand2.source = memop0;
		switch(size)
		{
			case 1: operands[threadid].operand2.value = (UINT64) ((UINT8 *)memop0)[0];
					break;
			case 2: operands[threadid].operand2.value = (UINT64) ((UINT16 *)memop0)[0];
					break;
			case 4: operands[threadid].operand2.value = (UINT64) ((UINT32 *)memop0)[0];
					break;
			case 8: operands[threadid].operand2.value = ((UINT64 *)memop0)[0];
					break;
		}
		operands[threadid].operand2.is_tainted = false;
		for( addr_it = tainted_addrs.begin(); addr_it != tainted_addrs.end(); addr_it++ )
			if( *addr_it == memop0 )
			{
				operands[threadid].operand2.is_tainted = true;
				break;
			}
	}
	else if( rregs_count == 2 && mems_count==0 ) /* ins reg, reg */
	{
		//fprintf(f, "[debug] ins reg, reg %d\n", memop_index);
		PIN_GetContextRegval(ctx, rregs[0], (UINT8 *)&register_value);
		operands[threadid].operand1.size = REG_Size(rregs[0]);
		operands[threadid].operand1.source = (ADDRINT)rregs[0];
		switch( operands[threadid].operand1.size )
		{
			case 1: operands[threadid].operand1.value = (UINT64) ((UINT8 *)register_value)[0];
					break;
			case 2: operands[threadid].operand1.value = (UINT64) ((UINT16 *)register_value)[0];
					break;
			case 4: operands[threadid].operand1.value = (UINT64) ((UINT32 *)register_value)[0];
					break;
			case 8: operands[threadid].operand1.value = ((UINT64 *)register_value)[0];
					break;
		}
		if( check_reg_taint( rregs[0], threadid ) )
			operands[threadid].operand1.is_tainted = true;
		else
			operands[threadid].operand1.is_tainted = false;

		PIN_GetContextRegval(ctx, rregs[1], (UINT8 *)&register_value);
		operands[threadid].operand2.size = REG_Size(rregs[1]);
		operands[threadid].operand2.source = (ADDRINT)rregs[1];
		switch( operands[threadid].operand2.size )
		{
			case 1: operands[threadid].operand2.value = (UINT64) ((UINT8 *)register_value)[0];
					break;
			case 2: operands[threadid].operand2.value = (UINT64) ((UINT16 *)register_value)[0];
					break;
			case 4: operands[threadid].operand2.value = (UINT64) ((UINT32 *)register_value)[0];
					break;
			case 8: operands[threadid].operand2.value = ((UINT64 *)register_value)[0];
					break;
		}
		if( check_reg_taint( rregs[1], threadid ) )
			operands[threadid].operand2.is_tainted = true;
		else
			operands[threadid].operand2.is_tainted = false;
	}
	else if( immediate_size > 0 && mems_count == 0 )  /* ins reg, imm */
	{
		//fprintf(f, "[debug] ins reg, imm %d\n", memop_index);
		PIN_GetContextRegval(ctx, rregs[0], (UINT8 *)&register_value);
		operands[threadid].operand1.size = REG_Size(rregs[0]);
		operands[threadid].operand1.source = (ADDRINT)rregs[0];
		switch( operands[threadid].operand1.size )
		{
			case 1: operands[threadid].operand1.value = (UINT64) ((UINT8 *)register_value)[0];
					break;
			case 2: operands[threadid].operand1.value = (UINT64) ((UINT16 *)register_value)[0];
					break;
			case 4: operands[threadid].operand1.value = (UINT64) ((UINT32 *)register_value)[0];
					break;
			case 8: operands[threadid].operand1.value = ((UINT64 *)register_value)[0];
					break;
		}
		if( check_reg_taint( rregs[0], threadid ) )
			operands[threadid].operand1.is_tainted = true;
		else
			operands[threadid].operand1.is_tainted = false;

		operands[threadid].operand2.size = immediate_size/8;
		operands[threadid].operand2.source = 0;
		switch(immediate_size)
		{
			case 8: operands[threadid].operand2.value = (UINT64) ((UINT8 *)&immediate)[0];
					break;
			case 16: operands[threadid].operand2.value = (UINT64) ((UINT16 *)&immediate)[0];
					break;
			case 32: operands[threadid].operand2.value = (UINT64) ((UINT32 *)&immediate)[0];
					break;
			case 64: operands[threadid].operand2.value = immediate;
					break;
		}
		operands[threadid].operand2.is_tainted = false;
	}
	else if( mems_count == 1 && immediate_size > 0 && memop_index == 0 )  /* ins [reg], imm */
	{
		//fprintf(f, "[debug] ins [mem], imm %d\n", memop_index);
		operands[threadid].operand1.size = size;
		operands[threadid].operand1.source = memop0;
		switch(size)
		{
			case 1: operands[threadid].operand1.value = (UINT64) ((UINT8 *)memop0)[0];
					break;
			case 2: operands[threadid].operand1.value = (UINT64) ((UINT16 *)memop0)[0];
					break;
			case 4: operands[threadid].operand1.value = (UINT64) ((UINT32 *)memop0)[0];
					break;
			case 8: operands[threadid].operand1.value = ((UINT64 *)memop0)[0];
					break;
		}
		operands[threadid].operand1.is_tainted = false;
		for( addr_it = tainted_addrs.begin(); addr_it != tainted_addrs.end(); addr_it++ )
			if( *addr_it == memop0 )
			{
				operands[threadid].operand1.is_tainted = true;
				break;
			}

		operands[threadid].operand2.size = immediate_size/8;
		operands[threadid].operand2.source = 0;
		switch(immediate_size)
		{
			case 8: operands[threadid].operand2.value = (UINT64) ((UINT8 *)&immediate)[0];
					break;
			case 16: operands[threadid].operand2.value = (UINT64) ((UINT16 *)&immediate)[0];
					break;
			case 32: operands[threadid].operand2.value = (UINT64) ((UINT32 *)&immediate)[0];
					break;
			case 64: operands[threadid].operand2.value = immediate;
					break;
		}
		operands[threadid].operand2.is_tainted = false;
	}
	else if( mems_count == 1 && memop_index == 0 )  /* ins [reg/imm], reg */
	{
		//fprintf(f, "[debug] ins [mem], reg %d\n", memop_index);
		operands[threadid].operand1.size = size;
		operands[threadid].operand1.source = memop0;
		switch(size)
		{
			case 1: operands[threadid].operand1.value = (UINT64) ((UINT8 *)memop0)[0];
					break;
			case 2: operands[threadid].operand1.value = (UINT64) ((UINT16 *)memop0)[0];
					break;
			case 4: operands[threadid].operand1.value = (UINT64) ((UINT32 *)memop0)[0];
					break;
			case 8: operands[threadid].operand1.value = ((UINT64 *)memop0)[0];
					break;
		}
		operands[threadid].operand1.is_tainted = false;
		for( addr_it = tainted_addrs.begin(); addr_it != tainted_addrs.end(); addr_it++ )
			if( *addr_it == memop0 )
			{
				operands[threadid].operand1.is_tainted = true;
				break;
			}

		PIN_GetContextRegval(ctx, rregs[1], (UINT8 *)&register_value);
		operands[threadid].operand2.size = REG_Size(rregs[1]);
		operands[threadid].operand2.source = (ADDRINT)rregs[1];
		switch( operands[threadid].operand2.size )
		{
			case 1: operands[threadid].operand2.value = (UINT64) ((UINT8 *)register_value)[0];
					break;
			case 2: operands[threadid].operand2.value = (UINT64) ((UINT16 *)register_value)[0];
					break;
			case 4: operands[threadid].operand2.value = (UINT64) ((UINT32 *)register_value)[0];
					break;
			case 8: operands[threadid].operand2.value = ((UINT64 *)register_value)[0];
					break;
		}
		if( check_reg_taint( rregs[1], threadid ) )
			operands[threadid].operand2.is_tainted = true;
		else
			operands[threadid].operand2.is_tainted = false;
	}
}

unsigned int offset = -1; /* индекс в tainted_data */
string concolic(REG reg, ADDRINT mem, UINT32 threadid, ADDRINT eip, CONTEXT * ctx, OPCODE opcode, UINT32 rregs_count, REG * rregs, UINT32 wregs_count, REG * wregs, UINT32 mems_count, UINT32 memop0_type, ADDRINT memop0, UINT32 memop1_type, ADDRINT memop1, UINT32 size, UINT32 memop_index, UINT64 immediate, UINT32 immediate_size)
{
	stringstream equation, expression;
	string expression_prev;
	if(XED_ICLASS_JB > opcode || opcode > XED_ICLASS_JZ)
		get_operands_value(threadid, ctx, rregs_count, rregs, wregs_count, wregs, mems_count, memop0_type, memop0, memop1_type, memop1, size, memop_index, immediate, immediate_size);

	if( ( opcode == XED_ICLASS_CMP) )
	{
		if( operands[threadid].operand1.is_tainted )
		{
			//fprintf(f, "x=SYM, ");
		}
		else
		{
			/*
			switch(operands[threadid].operand1.size)
			{
				case 1: fprintf(f, "x=%02x, ", (UINT8)operands[threadid].operand1.value); break;
				case 2: fprintf(f, "x=%04x, ", (UINT16)operands[threadid].operand1.value); break;
				case 4: fprintf(f, "x=%08x, ", (UINT32)operands[threadid].operand1.value); break;
				case 8: fprintf(f, "x=%016lx, ", (UINT64)operands[threadid].operand1.value); break;
			}
			*/
		}
		if( operands[threadid].operand2.is_tainted )
		{
			//fprintf(f, "y=SYM\n");
		}
		else
		{
			/*
			switch(operands[threadid].operand2.size)
			{
				case 1: fprintf(f, "y=%02x\n", (UINT8)operands[threadid].operand2.value); break;
				case 2: fprintf(f, "y=%04x\n", (UINT16)operands[threadid].operand2.value); break;
				case 4: fprintf(f, "y=%08x\n", (UINT32)operands[threadid].operand2.value); break;
				case 8: fprintf(f, "y=%016lx\n", (UINT64)operands[threadid].operand2.value); break;
			}
			*/
		}
	}
	else if( opcode == XED_ICLASS_TEST )
	{
		if( operands[threadid].operand1.is_tainted )
		{
			//fprintf(f, "x=SYM, ");
		}
		else
		{
			/*
			switch(operands[threadid].operand1.size)
			{
				case 1: fprintf(f, "x=%02x, ", (UINT8)operands[threadid].operand1.value); break;
				case 2: fprintf(f, "x=%04x, ", (UINT16)operands[threadid].operand1.value); break;
				case 4: fprintf(f, "x=%08x, ", (UINT32)operands[threadid].operand1.value); break;
				case 8: fprintf(f, "x=%016lx, ", (UINT64)operands[threadid].operand1.value); break;
			}
			*/
		}
		operands[threadid].operand2.value = 0;
		operands[threadid].operand2.size = 1;
		operands[threadid].operand2.is_tainted = false;
		//fprintf(f, "y=0\n");
	}
	else if( opcode == XED_ICLASS_ADD )
	{
		/* op1 = op1 + op2 */

		expression << "(";
		if(reg)
			expression_prev = symbolic_registers[threadid][reg];
		else if(mem)
			expression_prev = symbolic_memory[mem];

		if(operands[threadid].operand1.is_tainted)
			expression << expression_prev;
		else
			expression << "0x" << hex << operands[threadid].operand1.value;
		
		expression << " + ";

		if( operands[threadid].operand2.is_tainted )
			expression << expression_prev;
		else
			expression << "0x" << hex << operands[threadid].operand2.value;
		expression << ")";
		fprintf(f, "%s\n", expression.str().c_str());
	}
	else if( opcode == XED_ICLASS_SUB )
	{
		/* op1 = op1 - op2 */

		expression << "(";
		if(reg)
			expression_prev = symbolic_registers[threadid][reg];
		else if(mem)
			expression_prev = symbolic_memory[mem];

		if(operands[threadid].operand1.is_tainted)
			expression << expression_prev;
		else
			expression << "0x" << hex << operands[threadid].operand1.value;
		
		expression << " - ";

		if( operands[threadid].operand2.is_tainted )
			expression << expression_prev;
		else
			expression << "0x" << hex << operands[threadid].operand2.value;
		expression << ")";
		fprintf(f, "%s\n", expression.str().c_str());
	}
	else if( opcode == XED_ICLASS_MUL )
	{
		fprintf(f, "TODO =* %x\n", (UINT8)operands[threadid].operand1.value);
	}
	else if( opcode == XED_ICLASS_DIV )
	{
		fprintf(f, "TODO =/ %x\n", (UINT8)operands[threadid].operand1.value);
	}
	else if( opcode == XED_ICLASS_AND )
	{
		/* op1 = op1 & op2 */

		expression << "(";
		if(reg)
			expression_prev = symbolic_registers[threadid][reg];
		else if(mem)
			expression_prev = symbolic_memory[mem];

		if(operands[threadid].operand1.is_tainted)
			expression << expression_prev;
		else
			expression << "0x" << hex << operands[threadid].operand1.value;
		
		expression << " & ";

		if( operands[threadid].operand2.is_tainted )
			expression << expression_prev;
		else
			expression << "0x" << hex << operands[threadid].operand2.value;
		expression << ")";
		fprintf(f, "%s\n", expression.str().c_str());
	}
	else if( opcode == XED_ICLASS_OR )
	{
		/* op1 = op1 | op2 */
		
		expression << "(";
		if(reg)
			expression_prev = symbolic_registers[threadid][reg];
		else if(mem)
			expression_prev = symbolic_memory[mem];

		if(operands[threadid].operand1.is_tainted)
			expression << expression_prev;
		else
			expression << "0x" << hex << operands[threadid].operand1.value;
		
		expression << " | ";

		if( operands[threadid].operand2.is_tainted )
			expression << expression_prev;
		else
			expression << "0x" << hex << operands[threadid].operand2.value;
		expression << ")";
		fprintf(f, "%s\n", expression.str().c_str());
	}
	else if( opcode == XED_ICLASS_XOR )
	{
		/* op1 = op1 ^ op2 */
		
		expression << "(";
		if(reg)
			expression_prev = symbolic_registers[threadid][reg];
		else if(mem)
			expression_prev = symbolic_memory[mem];

		if(operands[threadid].operand1.is_tainted)
			expression << expression_prev;
		else
			expression << "0x" << hex << operands[threadid].operand1.value;
		
		expression << " ^ ";

		if( operands[threadid].operand2.is_tainted )
			expression << expression_prev;
		else
			expression << "0x" << hex << operands[threadid].operand2.value;
		expression << ")";
		fprintf(f, "%s\n", expression.str().c_str());
	}
	else if( opcode == XED_ICLASS_SHL )
	{
		/* op1 = op1 << op2 */
		
		expression << "(";
		if(reg)
			expression_prev = symbolic_registers[threadid][reg];
		else if(mem)
			expression_prev = symbolic_memory[mem];

		if(operands[threadid].operand1.is_tainted)
			expression << expression_prev;
		else
			expression << "0x" << hex << operands[threadid].operand1.value;
		
		expression << " << ";

		if( operands[threadid].operand2.is_tainted )
			expression << expression_prev;
		else
			expression << "0x" << hex << operands[threadid].operand2.value;
		expression << ")";
		fprintf(f, "%s\n", expression.str().c_str());
	}
	else if( opcode == XED_ICLASS_SHR )
	{
		/* op1 = op1 >> op2 */

		expression << "(";
		if(reg)
			expression_prev = symbolic_registers[threadid][reg];
		else if(mem)
			expression_prev = symbolic_memory[mem];

		if(operands[threadid].operand1.is_tainted)
			expression << expression_prev;
		else
			expression << "0x" << hex << operands[threadid].operand1.value;
		
		expression << " >> ";

		if( operands[threadid].operand2.is_tainted )
			expression << expression_prev;
		else
			expression << "0x" << hex << operands[threadid].operand2.value;
		expression << ")";
		fprintf(f, "%s\n", expression.str().c_str());
	}
	else if( opcode == XED_ICLASS_NEG )
	{
		//fprintf(f, "!%x\n", (UINT8)operands[threadid].operand1.value);
	}
	else if( opcode == XED_ICLASS_NOT )
	{
		//fprintf(f, "!%x\n", (UINT8)operands[threadid].operand1.value);
	}

	else if( opcode == XED_ICLASS_JB || opcode == XED_ICLASS_JL )
	{
		/* a < b */

		equation << equations[offset] << "&(";
		if(reg)
			expression_prev = symbolic_registers[threadid][reg];
		else if(mem)
			expression_prev = symbolic_memory[mem];

		if( operands[threadid].operand1.is_tainted )
			equation << expression_prev;
		else
			equation << "0x" << hex << operands[threadid].operand1.value;

		equation << " < ";

		if( operands[threadid].operand2.is_tainted )
			equation << expression_prev;
		else
			equation << "0x" << hex << operands[threadid].operand2.value;
		equation << ")";
		equations[offset] = equation.str();
		fprintf(f, "%s\n", equations[offset].c_str());
	}
	else if( opcode == XED_ICLASS_JNB || opcode == XED_ICLASS_JNL )
	{
		/* a >= b */

		equation << equations[offset] << "&(";
		if(reg)
			expression_prev = symbolic_registers[threadid][reg];
		else if(mem)
			expression_prev = symbolic_memory[mem];

		if( operands[threadid].operand1.is_tainted )
			equation << expression_prev;
		else
			equation << "0x" << hex << operands[threadid].operand1.value;

		equation << " >= ";

		if( operands[threadid].operand2.is_tainted )
			equation << expression_prev;
		else
			equation << "0x" << hex << operands[threadid].operand2.value;
		equation << ")";
		equations[offset] = equation.str();
		fprintf(f, "%s\n", equations[offset].c_str());
	}
	else if( opcode == XED_ICLASS_JBE || opcode == XED_ICLASS_JLE )
	{
		/* a <= b */

		equation << equations[offset] << "&(";
		if(reg)
			expression_prev = symbolic_registers[threadid][reg];
		else if(mem)
			expression_prev = symbolic_memory[mem];

		if( operands[threadid].operand1.is_tainted )
			equation << expression_prev;
		else
			equation << "0x" << hex << operands[threadid].operand1.value;

		equation << " <= ";

		if( operands[threadid].operand2.is_tainted )
			equation << expression_prev;
		else
			equation << "0x" << hex << operands[threadid].operand2.value;
		equation << ")";
		equations[offset] = equation.str();
		fprintf(f, "%s\n", equations[offset].c_str());
	}
	else if( opcode == XED_ICLASS_JNBE || opcode == XED_ICLASS_JNLE )
	{
		/* a > b */
		
		equation << equations[offset] << "&(";
		if(reg)
			expression_prev = symbolic_registers[threadid][reg];
		else if(mem)
			expression_prev = symbolic_memory[mem];

		if( operands[threadid].operand1.is_tainted )
			equation << expression_prev;
		else
			equation << "0x" << hex << operands[threadid].operand1.value;

		equation << " > ";

		if( operands[threadid].operand2.is_tainted )
			equation << expression_prev;
		else
			equation << "0x" << hex << operands[threadid].operand2.value;
		equation << ")";
		equations[offset] = equation.str();
		fprintf(f, "%s\n", equations[offset].c_str());
	}
	else if( opcode == XED_ICLASS_JZ )
	{
		/* == */

		equation << equations[offset] << "&(";
		if(reg)
			expression_prev = symbolic_registers[threadid][reg];
		else if(mem)
			expression_prev = symbolic_memory[mem];

		if( operands[threadid].operand1.is_tainted )
			equation << expression_prev;
		else
			equation << "0x" << hex << operands[threadid].operand1.value;

		equation << " == ";

		if( operands[threadid].operand2.is_tainted )
			equation << expression_prev;
		else
			equation << "0x" << hex << operands[threadid].operand2.value;
		equation << ")";
		equations[offset] = equation.str();
		fprintf(f, "%s\n", equations[offset].c_str());
	}
	else if( opcode == XED_ICLASS_JNZ )
	{
		/* != */

		equation << equations[offset] << "&(";
		if(reg)
			expression_prev = symbolic_registers[threadid][reg];
		else if(mem)
			expression_prev = symbolic_memory[mem];

		if( operands[threadid].operand1.is_tainted )
			equation << expression_prev;
		else
			equation << "0x" << hex << operands[threadid].operand1.value;

		equation << " != ";

		if( operands[threadid].operand2.is_tainted )
			equation << expression_prev;
		else
			equation << "0x" << hex << operands[threadid].operand2.value;
		equation << ")";
		equations[offset] = equation.str();
		fprintf(f, "%s\n", equations[offset].c_str());
	}
	else if( opcode == XED_ICLASS_JS )
	{
		/* a < 0 */
		
		equation << equations[offset] << "&(";
		if(reg)
			expression_prev = symbolic_registers[threadid][reg];
		else if(mem)
			expression_prev = symbolic_memory[mem];

		if( operands[threadid].operand1.is_tainted )
			equation << expression_prev;
		else
			equation << "0x" << hex << operands[threadid].operand1.value;

		equation << " < ";
		equation << "0";
		equation << ")";
		equations[offset] = equation.str();
		fprintf(f, "%s\n", equations[offset].c_str());
	}
	else if( opcode == XED_ICLASS_JNS )
	{
		/* a > 0 */
		
		equation << equations[offset] << "&(";
		if(reg)
			expression_prev = symbolic_registers[threadid][reg];
		else if(mem)
			expression_prev = symbolic_memory[mem];

		if( operands[threadid].operand1.is_tainted )
			equation << expression_prev;
		else
			equation << "0x" << hex << operands[threadid].operand1.value;

		equation << " > ";
		equation << "0";
		equation << ")";
		equations[offset] = equation.str();
		fprintf(f, "%s\n", equations[offset].c_str());
	}
	else if( opcode == XED_ICLASS_JO )
	{
		
	}
	else if( opcode == XED_ICLASS_JNO )
	{
		
	}
	else if( opcode == XED_ICLASS_JP )
	{
		/* a % 2 == 0 */
		
		equation << equations[offset] << "&(";
		if(reg)
			expression_prev = symbolic_registers[threadid][reg];
		else if(mem)
			expression_prev = symbolic_memory[mem];

		if( operands[threadid].operand1.is_tainted )
			equation << expression_prev;
		else
			equation << "0x" << hex << operands[threadid].operand1.value;

		equation << "%%2 == ";
		equation << "0";
		equation << ")";
		equations[offset] = equation.str();
		fprintf(f, "%s\n", equations[offset].c_str());
	}		
	else if( opcode == XED_ICLASS_JNP )
	{
		/* a % 2 != 0 */
		
		equation << equations[offset] << "&(";
		if(reg)
			expression_prev = symbolic_registers[threadid][reg];
		else if(mem)
			expression_prev = symbolic_memory[mem];

		if( operands[threadid].operand1.is_tainted )
			equation << expression_prev;
		else
			equation << "0x" << hex << operands[threadid].operand1.value;

		equation << "%%2 != ";
		equation << "0";
		equation << ")";
		equations[offset] = equation.str();
		fprintf(f, "%s\n", equations[offset].c_str());
	}
	else if( opcode == XED_ICLASS_JCXZ )
	{
		//fprintf(f, "(ecx == 0)\n");
	}
	else if( opcode == XED_ICLASS_JECXZ )
	{
		//fprintf(f, "(ecx != 0)\n");
	}
	else if( opcode == XED_ICLASS_JRCXZ )
	{
		//fprintf(f, "(rcx == 0)\n");
	}
	return expression.str();
}

void track_operations(OPCODE opcode, ADDRINT addr)
{
	bool is_cmp = ( opcode == XED_ICLASS_CMP) || ( opcode == XED_ICLASS_TEST );
	if(is_cmp == true)
		tainted_operations[addr] = 2;
	else if(tainted_operations[addr] != 2)
		tainted_operations[addr] = 1;
}

void taint(UINT32 threadid, ADDRINT eip, CONTEXT * ctx, OPCODE opcode, UINT32 rregs_count, REG * rregs, UINT32 wregs_count, REG * wregs, UINT32 mems_count, UINT32 memop0_type, ADDRINT memop0, UINT32 memop1_type, ADDRINT memop1, UINT32 size, UINT32 memop_index, UINT64 immediate, UINT32 immediate_size)
{
	UINT32 i, j, is_spread = 0;
	list <ADDRINT>::iterator addr_it;
	ADDRINT taint_memory_read = 0, taint_memory_write = 0;
	REG reg = (REG) 0;
	UINT8 register_value[128] = {0};
	string expression = "";

	ins_count++;

	if(ins_count % 1000000 == 0)
	{
		fprintf(f, "[*] %lu\n", ins_count);
		fflush(f);
	}

	if( opcode == XED_ICLASS_XOR && rregs_count > 1 && rregs[0] == rregs[1] )
		return;

	if(memop0_type&READ) find_tainted_data(memop0);
	if(memop1_type&READ) find_tainted_data(memop1);

	for( i = 0; i < rregs_count; i++ ) /* каждый из читаемых регистров */
	{
		/* содержание в регистре помеченных данных */
		if( check_reg_taint( rregs[i], threadid ) ) /* проверить - не помечен ли регистр */
		{
			is_spread = 1;
			//if( ( reg = get_full_reg(rregs[i]) ) != 0 )
			//if( ( reg = REG_FullRegName(rregs[i]) ) != 0 )
			if( ( reg = rregs[i] ) != 0 )
			{
				PIN_GetContextRegval(ctx, reg, (UINT8 *)&register_value);
			}
			break;
		}
	}

	/* прямое обращение к памяти на чтение */
	if( mems_count != 0 && (memop0_type&READ || memop1_type&READ) && !is_spread ) /* если есть читаемые операнды памяти и не было найдено распространение */
	{
		for( addr_it = tainted_addrs.begin(); addr_it != tainted_addrs.end(); addr_it++ )
		{
			if( memop0_type&READ && *addr_it == memop0 )  /* совпадает ли 1 операнд памяти с помеченной памятью */
			{
				taint_memory_read = memop0;
				is_spread = 1; 	/* обнаружено распространение памяти */
				offset = tainted_offsets[memop0];
				break;
			}
			if( memop1_type&READ && *addr_it == memop1 ) 	/* совпадает ли 2 операнд памяти с помеченной памятью */
			{
				taint_memory_read = memop1;
				is_spread = 1; 	/* обнаружено распространение памяти */
				offset = tainted_offsets[memop1];
				break;
			}
		}
	}

	
	if( is_spread ) /* если есть распространение регистров/памяти */
	{

		if( (eip >= low_boundary && eip < high_boundary) || (low_boundary == 0 && high_boundary == 0) )
			expression = concolic(reg, taint_memory_read, threadid, eip, ctx, opcode, rregs_count, rregs, wregs_count, wregs, mems_count, memop0_type, memop0, memop1_type, memop1, size, memop_index, immediate, immediate_size);

		fprintf(f, "[debug] concolic: %s\n", expression.c_str());
		/* прямое обращение к памяти на запись */
		if( mems_count != 0 && (memop0_type&WRITE || memop1_type&WRITE) ) /* если есть записываемый операнд памяти */
		{
			if(memop0_type&WRITE)
			{
				for(i = 0; i < size; i++)
				{
					add_mem_taint( memop0+i ); /* пометить записываемый 1 операнд памяти */
					tainted_offsets[memop0+i] = offset+i;
					if(expression != "")
						add_symbolic_memory( memop0+i, expression );
					else
					{
						if(reg)
							add_symbolic_memory( memop0+i, symbolic_registers[threadid][reg] );
						else if(taint_memory_read)
							add_symbolic_memory( memop0+i, symbolic_memory[taint_memory_read] );
					}

				}
				taint_memory_write = memop0;
			}
			if(memop1_type&WRITE)
			{
				for(i = 0; i < size; i++)
				{
					add_mem_taint( memop1+i ); /* пометить записываемый 2 операнд памяти */
					tainted_offsets[memop1+i] = offset+i;
					if(expression != "")
						add_symbolic_memory( memop0+i, expression );
					else
					{
						if(reg)
							add_symbolic_memory( memop0+i, symbolic_registers[threadid][reg] );
						else if(taint_memory_read)
							add_symbolic_memory( memop0+i, symbolic_memory[taint_memory_read] );
					}
				}
				taint_memory_write = memop1;
			}
		}
		/* запись регистра */
		for( j = 0; j < wregs_count; j++ )  /* каждый из записываемых регистров */
		{
			add_reg_taint( wregs[j], threadid );  /* пометить записываемый регистр */
			if(expression != "")
				add_symbolic_register( wregs[j], threadid, expression );
			else
			{
				if(reg)
					add_symbolic_register( wregs[j], threadid, symbolic_registers[threadid][reg] );
				else if(taint_memory_read)
					add_symbolic_register( wregs[j], threadid, symbolic_memory[taint_memory_read] );
			}
		}
	}
	else  /* если распространение не было найдено */
	{
		for( i = 0; i < wregs_count; i++ ) 	/* каждый из записываемых регистров */
		{
			del_reg_taint( wregs[i], threadid );
			del_symbolic_register( wregs[i], threadid );
		}
		
		if(memop0_type&WRITE)
		{
			del_mem_taint( memop0 );
			del_symbolic_memory( memop0 );
		}
		if(memop1_type&WRITE)
		{
			del_mem_taint( memop1 );
			del_symbolic_memory( memop0 );
		}
	}

	if(memop0_type)
		save_page(memop0);
	if(memop1_type)
		save_page(memop1);

	if(is_spread)
		if( (eip >= low_boundary && eip < high_boundary) || (low_boundary == 0 && high_boundary == 0) )
		{
			for(i = 0; i < size; i++)
			{
				track_operations(opcode, offset+i);
			}
			fprintf(f, "[+] %s " HEX_FMT ":%u:%lu:", get_module_name(eip), eip - get_module_base(eip), threadid, ins_count);
			if(taint_memory_read)
			{
				switch(size)
				{
					case 8:
						fprintf( f, " *" HEX_FMT " -> %016lX", taint_memory_read, *((unsigned long int *)taint_memory_read) );
						break;
					case 4:
						fprintf( f, " *" HEX_FMT " -> %08X", taint_memory_read, *((unsigned int *)taint_memory_read) );
						break;
					case 2:
						fprintf( f, " *" HEX_FMT " -> %04X", taint_memory_read, *((unsigned short *)taint_memory_read) );
						break;
					case 1:
						fprintf( f, " *" HEX_FMT " -> %02X", taint_memory_read, *((unsigned char *)taint_memory_read) );
						break;
				}
				telescope( *((int *)taint_memory_read), 1 );
			}
			if(taint_memory_write)
				fprintf( f, " *" HEX_FMT " <- ;", taint_memory_write );
			if(reg)
			{
				switch(REG_Size(reg))
				{
					case 1:
						fprintf( f, " %s=%02X;", REG_StringShort(reg).c_str(), (UINT8)register_value[0] );
						break;
					case 2:
						fprintf( f, " %s=%04X;", REG_StringShort(reg).c_str(), (UINT16)register_value[0] );
						break;
					case 4:
						fprintf( f, " %s=%08X;", REG_StringShort(reg).c_str(), (UINT32)register_value[0] );
						break;
					#if defined(X64)
						case 8:
							fprintf( f, " %s=%016lX;", REG_StringShort(reg).c_str(), (UINT64)register_value[0] );
							break;
						case 16:
							fprintf( f, " %s=%016lX%016lX;", REG_StringShort(reg).c_str(), ((UINT64 *)register_value)[1], ((UINT64 *)register_value)[0] );
							break;
					#else
						case 8:
							fprintf( f, " %s=%08X%08X;", REG_StringShort(reg).c_str(), ((UINT32 *)register_value)[1], ((UINT32 *)register_value)[0] );
							break;
						case 16:
							fprintf( f, " %s=%08X%08X%08X%08X;", REG_StringShort(reg).c_str(), ((UINT32 *)register_value)[3], ((UINT32 *)register_value)[2], ((UINT32 *)register_value)[1], ((UINT32 *)register_value)[0] );
							break;
					#endif
				}
			}
			fprintf(f, " [0x%x]\n", offset);
			fflush(f);
		}
}


void ins_instrument(INS ins, VOID * v)
{
	REG *rregs, *wregs;
	int rregs_count = 0, wregs_count = 0;
	int i, mems_count, operands_count, immediate_size = 0;
	UINT64 immediate = 0;
	ADDRINT eip;
	rregs_count = INS_MaxNumRRegs(ins);
	wregs_count = INS_MaxNumWRegs(ins);
	mems_count = INS_MemoryOperandCount(ins);
	operands_count = INS_OperandCount(ins);
	eip = INS_Address(ins);
	rregs = (REG *) malloc( rregs_count * sizeof(REG) );
	wregs = (REG *) malloc( wregs_count * sizeof(REG) );

	if( rregs_count == -1 || wregs_count == -1 || mems_count == -1 )
	{
		fprintf(f, "[!] error " HEX_FMT "\n", eip);
		fflush(f);
		return;
	}

	for( i = 0; i < operands_count; i++ )
	{
		if( INS_OperandIsImmediate(ins, i) )
		{
			immediate = INS_OperandImmediate(ins, i);
			immediate_size = INS_OperandWidth(ins, i);
		}
	}

	if( rregs_count || wregs_count || mems_count )
	{
		for( i = 0; i < rregs_count; i++)
			rregs[i] = INS_RegR(ins, i);
		for( i = 0; i < wregs_count; i++)
			wregs[i] = INS_RegW(ins, i);

		switch( mems_count )
		{
			case 0: INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) taint,
					IARG_UINT32, PIN_ThreadId(),
					IARG_ADDRINT, eip,
					IARG_CONTEXT,
					IARG_UINT32, INS_Opcode(ins),
					IARG_UINT32, rregs_count,
					IARG_PTR, rregs,
					IARG_UINT32, wregs_count,
					IARG_PTR, wregs,
					IARG_UINT32, 0, 	/* mem_operands count */
					IARG_UINT32, 0, 	/* mem_op0 type */
					IARG_UINT32, 0, 	/* mem_op0 value */
					IARG_UINT32, 0, 	/* mem_op1 type */
					IARG_UINT32, 0, 	/* mem_op1 value */
					IARG_UINT32, 0, 	/* mem_read_size */
					IARG_UINT32, 0, 	/* mem_op1_index */
					IARG_UINT64, immediate,
					IARG_UINT32, immediate_size,					
					IARG_END);
					break;
			case 1: INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) taint,
					IARG_UINT32, PIN_ThreadId(),
					IARG_ADDRINT, eip,
					IARG_CONTEXT,
					IARG_UINT32, INS_Opcode(ins),
					IARG_UINT32, rregs_count,
					IARG_PTR, rregs,
					IARG_UINT32, wregs_count,
					IARG_PTR, wregs,
					IARG_UINT32, 1,
					IARG_UINT32, INS_MemoryOperandIsRead(ins, 0) ? ( INS_MemoryOperandIsWritten(ins, 0)? READ_WRITE : READ ) : WRITE,
					IARG_MEMORYOP_EA, 0,
					IARG_UINT32, 0,
					IARG_UINT32, 0,
					IARG_MEMORYREAD_SIZE,
					IARG_UINT32, INS_MemoryOperandIndexToOperandIndex(ins, 0),
					IARG_UINT64, immediate,
					IARG_UINT32, immediate_size,
					IARG_END);
					break;
			case 2: INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) taint,
					IARG_UINT32, PIN_ThreadId(),
					IARG_ADDRINT, eip,
					IARG_CONTEXT,
					IARG_UINT32, INS_Opcode(ins),
					IARG_UINT32, rregs_count,
					IARG_PTR, rregs,
					IARG_UINT32, wregs_count,
					IARG_PTR, wregs,
					IARG_UINT32, 2,
					IARG_UINT32, INS_MemoryOperandIsRead(ins, 0) ? ( INS_MemoryOperandIsWritten(ins, 0)? READ_WRITE : READ ) : WRITE,
					IARG_MEMORYOP_EA, 0,
					IARG_UINT32, INS_MemoryOperandIsRead(ins, 1) ? ( INS_MemoryOperandIsWritten(ins, 1)? READ_WRITE : READ ) : WRITE,
					IARG_MEMORYOP_EA, 1,
					IARG_MEMORYREAD_SIZE,
					IARG_UINT32, INS_MemoryOperandIndexToOperandIndex(ins, 0),
					IARG_UINT64, immediate,
					IARG_UINT32, immediate_size,
					IARG_END);
					break;
		}
	}
}

void img_instrument(IMG img, VOID * v)
{
	MODULE *module;
	module = (MODULE *)malloc(sizeof(MODULE));
	module->module = IMG_Name(img).c_str();
	module->low = IMG_LowAddress(img);
	module->high = IMG_HighAddress(img);
	modules.push_back(*module);
	//modules.push_back( (MODULE){ .module = IMG_Name(img).c_str(), .low = IMG_LowAddress(img), .high = IMG_HighAddress(img) } );
	if(need_module != "" && strcasestr( IMG_Name(img).c_str(), need_module.c_str() ) )
	{
		fprintf( f, "[+] module instrumented: " HEX_FMT " " HEX_FMT " %s\n", IMG_LowAddress(img), IMG_HighAddress(img), IMG_Name(img).c_str() );
		low_boundary = IMG_LowAddress(img);
		high_boundary = IMG_HighAddress(img);
	}
	else
		fprintf( f, "[*] module " HEX_FMT " " HEX_FMT " %s\n", IMG_LowAddress(img), IMG_HighAddress(img), IMG_Name(img).c_str() );
	fflush(f);
}

void fini(INT32 code, VOID *v)
{
	unsigned int i;
	for( i = 0; i < taint_data_len; i++ )
	{
		if(i % 0x10 == 0)
			fprintf(f, "\n0x%04x:\t", i);
		if( taint_size == 0 || (i >= taint_offset && i < taint_offset+taint_size) )
		{
			switch( tainted_operations[i] )
			{
				case 2:
					fprintf(f, "cc ");
					break;
				case 1:
					fprintf(f, "rr ");
					break;
				default:
					fprintf(f, "** ");
					break;
			}
		}
		else
			fprintf(f, "-- ");
	}
	
	fflush(f);
	fclose(f);
}

EXCEPT_HANDLING_RESULT internal_exception(THREADID tid, EXCEPTION_INFO *pExceptInfo, PHYSICAL_CONTEXT *pPhysCtxt, VOID *v)
{
  fprintf( f, "[!] " HEX_FMT " %s\n", PIN_GetPhysicalContextReg(pPhysCtxt, REG_INST_PTR), PIN_ExceptionToString(pExceptInfo).c_str() );
  fflush(f);
  return EHR_UNHANDLED;
}

int main(int argc, char ** argv)
{
	const char *outfile_name, *taint_data_filename;
	if( PIN_Init(argc, argv) )
		return -1;

	PIN_InitSymbols();
	IMG_AddInstrumentFunction(img_instrument, 0);
	INS_AddInstrumentFunction(ins_instrument, 0);
	PIN_AddFiniFunction(fini, 0);
	
	low_boundary = Knob_from.Value();
    high_boundary = Knob_to.Value();
    need_module = Knob_module.Value();
    taint_offset = Knob_offset.Value();
    taint_size = Knob_size.Value();

    taint_data_filename = Knob_taint.Value().c_str();
    taint_data_file = fopen(taint_data_filename, "rb");
    taint_data = (unsigned char *) malloc(MAX_TAINT_DATA);
    taint_data_len = fread(taint_data, 1, MAX_TAINT_DATA, taint_data_file);
    fclose(taint_data_file);

	outfile_name = Knob_outfile.Value().c_str();
	f = fopen(outfile_name, "w");
	fprintf(f, "[*] taint data %d bytes:\n", taint_data_len);
	for(unsigned int i = 0 ; i < taint_data_len; i++)
	{
		if(i%0x10 == 0)
			fprintf(f, "\n[*] 0x%04x:\t", i);
		fprintf(f, "%02X ", taint_data[i]);
	}
	fprintf(f, "\n");

	PIN_AddInternalExceptionHandler(internal_exception, 0);
	PIN_StartProgram();
	return 0;
}
