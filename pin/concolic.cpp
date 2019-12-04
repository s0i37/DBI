#include <pin.H>
#include "z3++.h"
#include <stdio.h>
#include <list>
#include <map>

#define VERSION "0.10"
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

list <ADDRINT> pages;
list <MODULE> modules;
list <ADDRINT> tainted_addrs;
map <ADDRINT, unsigned int> tainted_offsets;
map <ADDRINT, unsigned int> tainted_operations;
map < int, list <REG> > tainted_regs;

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
KNOB<string> Knob_outfile(KNOB_MODE_WRITEONCE,  "pintool", "outfile", "taint.log", "Output file");
KNOB<ADDRINT> Knob_from(KNOB_MODE_WRITEONCE, "pintool", "from", "0", "start address (absolute) for taint");
KNOB<ADDRINT> Knob_to(KNOB_MODE_WRITEONCE, "pintool", "to", "0", "stop address (absolute) for taint");
KNOB<string> Knob_module(KNOB_MODE_WRITEONCE,  "pintool", "module", "", "taint this module");
KNOB<string> Knob_taint(KNOB_MODE_WRITEONCE,  "pintool", "taint", "", "taint this data");
KNOB<UINT32> Knob_offset(KNOB_MODE_WRITEONCE,  "pintool", "offset", "0", "from offset (subdata)");
KNOB<UINT32> Knob_size(KNOB_MODE_WRITEONCE,  "pintool", "size", "0", "size bytes (subdata)");


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

REG get_full_reg(REG reg)
{
	switch(reg)
	{
		case REG_GAX:
	#if defined(X64)
		case REG_EAX:
	#endif
		case REG_AX:
		case REG_AH:
		case REG_AL:
			return REG_GAX;

		case REG_GCX:
	#if defined(X64)
		case REG_ECX:
	#endif
		case REG_CX:
		case REG_CH:
		case REG_CL:
			return REG_GCX;

		case REG_GDX:
	#if defined(X64)
		case REG_EDX:
	#endif
		case REG_DX:
		case REG_DH:
		case REG_DL:
			return REG_GDX;

		case REG_GBX:
	#if defined(X64)
		case REG_EBX:
	#endif
		case REG_BX:
		case REG_BH:
		case REG_BL:
			return REG_GBX;

	//	case REG_STACK_PTR:
	//		return REG_STACK_PTR;

		case REG_GBP:
	#if defined(X64)
		case REG_EBP:
	#endif
		case REG_BP:
			return REG_GBP;

		case REG_GDI:
	#if defined(X64)
		case REG_EDI:
	#endif
		case REG_DI:
			return REG_GDI;

		case REG_GSI:
	#if defined(X64)
		case REG_ESI:
	#endif
		case REG_SI:
			return REG_GSI;

	#if defined(X64)
		case REG_R8:
		case REG_R8D:
    	case REG_R8W:
    	case REG_R8B:
    		return REG_R8;
    #endif

    #if defined(X64)
    	case REG_R9:
		case REG_R9D:
    	case REG_R9W:
    	case REG_R9B:
    		return REG_R9;
    #endif

    #if defined(X64)
    	case REG_R10:
		case REG_R10D:
    	case REG_R10W:
    	case REG_R10B:
    		return REG_R10;
    #endif

    #if defined(X64)
    	case REG_R11:
		case REG_R11D:
    	case REG_R11W:
    	case REG_R11B:
    		return REG_R11;
    #endif

    #if defined(X64)
    	case REG_R12:
		case REG_R12D:
    	case REG_R12W:
    	case REG_R12B:
    		return REG_R12;
    #endif

    #if defined(X64)
    	case REG_R13:
		case REG_R13D:
    	case REG_R13W:
    	case REG_R13B:
    		return REG_R13;
    #endif

    #if defined(X64)
    	case REG_R14:
		case REG_R14D:
    	case REG_R14W:
    	case REG_R14B:
    		return REG_R14;
    #endif

    #if defined(X64)
    	case REG_R15:
		case REG_R15D:
    	case REG_R15W:
    	case REG_R15B:
    		return REG_R15;
    #endif

		default:
			return (REG) 0;
	}
}

string get_reg_name(REG reg)
{
	switch(reg)
	{
	#if defined(X64)
		case REG_GAX:
			return "RAX";
		case REG_EAX:
			return "EAX";
	#elif defined(X32)
		case REG_GAX:
			return "EAX";
	#endif
		case REG_AX:
			return "AX";
		case REG_AH:
			return "AH";
		case REG_AL:
			return "AL";

	#if defined(X64)
		case REG_GCX:
			return "RCX";
		case REG_ECX:
			return "ECX";
	#elif defined(X32)
		case REG_GCX:
			return "ECX";
	#endif
		case REG_CX:
			return "CX";
		case REG_CH:
			return "CH";
		case REG_CL:
			return "CL";

	#if defined(X64)
		case REG_GDX:
			return "RDX";
		case REG_EDX:
			return "EDX";
	#elif defined(X32)
		case REG_GDX:
			return "EDX";
	#endif
		case REG_DX:
			return "DX";
		case REG_DH:
			return "DH";
		case REG_DL:
			return "DL";

	#if defined(X64)
		case REG_GBX:
			return "RBX";
		case REG_EBX:
			return "EBX";
	#elif defined(X32)
		case REG_GBX:
			return "EBX";
	#endif
		case REG_BX:
			return "BX";
		case REG_BH:
			return "BH";
		case REG_BL:
			return "BL";

	#if defined(X64)
		case REG_GBP:
			return "RBP";
		case REG_EBP:
			return "EBP";
	#elif defined(X32)
		case REG_GBP:
			return "EBP";
	#endif
		case REG_BP:
			return "BP";

	#if defined(X64)
		case REG_GDI:
			return "RDI";
		case REG_EDI:
			return "EDI";
	#elif defined(X32)
		case REG_GDI:
			return "EDI";
	#endif
		case REG_DI:
			return "DI";

	#if defined(X64)
		case REG_GSI:
			return "RSI";
		case REG_ESI:
			return "ESI";
	#elif defined(X32)
		case REG_GSI:
			return "ESI";
	#endif
		case REG_SI:
			return "SI";

	#if defined(X64)
		case REG_R8:
			return "R8";
		case REG_R8D:
			return "R8D";
    	case REG_R8W:
    		return "R8W";
    	case REG_R8B:
    		return "R8B";
    #endif

    #if defined(X64)
		case REG_R9:
			return "R9";
		case REG_R9D:
			return "R9D";
    	case REG_R9W:
    		return "R9W";
    	case REG_R9B:
    		return "R9B";
    #endif

    #if defined(X64)
		case REG_R10:
			return "R10";
		case REG_R10D:
			return "R10D";
    	case REG_R10W:
    		return "R10W";
    	case REG_R10B:
    		return "R10B";
    #endif

    #if defined(X64)
		case REG_R11:
			return "R11";
		case REG_R11D:
			return "R11D";
    	case REG_R11W:
    		return "R11W";
    	case REG_R11B:
    		return "R11B";
    #endif

    #if defined(X64)
		case REG_R12:
			return "R12";
		case REG_R12D:
			return "R12D";
    	case REG_R12W:
    		return "R12W";
    	case REG_R12B:
    		return "R12B";
    #endif

    #if defined(X64)
		case REG_R13:
			return "R13";
		case REG_R13D:
			return "R13D";
    	case REG_R13W:
    		return "R13W";
    	case REG_R13B:
    		return "R13B";
    #endif

    #if defined(X64)
		case REG_R14:
			return "R14";
		case REG_R14D:
			return "R14D";
    	case REG_R14W:
    		return "R14W";
    	case REG_R14B:
    		return "R14B";
    #endif

    #if defined(X64)
		case REG_R15:
			return "R15";
		case REG_R15D:
			return "R15D";
    	case REG_R15W:
    		return "R15W";
    	case REG_R15B:
    		return "R15B";
    #endif

		default:
			return "UNK";
	}
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
				add_mem_taint(mem + i);
		}
		else
			add_mem_taint(mem + i);
		tainted_offsets[mem+i] = i;
	}
	fprintf(f, "\n");
}

void concolic(UINT32 threadid, ADDRINT eip, CONTEXT * ctx, OPCODE opcode, UINT32 rregs_count, REG * rregs, UINT32 wregs_count, REG * wregs, UINT32 mems_count, UINT32 memop0_type, ADDRINT memop0, UINT32 memop1_type, ADDRINT memop1, UINT32 size)
{
	if( ( opcode == XED_ICLASS_CMP) || ( opcode == XED_ICLASS_TEST ) )
	{
		
	}
	else if( opcode == XED_ICLASS_ADD )
	{

	}
	else if( opcode == XED_ICLASS_SUB )
	{

	}
	else if( opcode == XED_ICLASS_MUL )
	{
		
	}
	else if( opcode == XED_ICLASS_DIV )
	{
		
	}
	else if( opcode == XED_ICLASS_AND )
	{

	}
	else if( opcode == XED_ICLASS_OR )
	{

	}
	else if( opcode == XED_ICLASS_XOR )
	{

	}
	else if( opcode == XED_ICLASS_NEG )
	{

	}
	else if( opcode == XED_ICLASS_NOT )
	{

	}
}

void track_operations(OPCODE opcode, ADDRINT addr)
{
	bool is_cmp = ( opcode == XED_ICLASS_CMP) || ( opcode == XED_ICLASS_TEST );
	if(is_cmp == true)
		tainted_operations[addr] = 2;
	else if(tainted_operations[addr] != 2)
		tainted_operations[addr] = 1;
}

unsigned int offset = -1; /* индекс в tainted_data */
void taint(UINT32 threadid, ADDRINT eip, CONTEXT * ctx, OPCODE opcode, UINT32 rregs_count, REG * rregs, UINT32 wregs_count, REG * wregs, UINT32 mems_count, UINT32 memop0_type, ADDRINT memop0, UINT32 memop1_type, ADDRINT memop1, UINT32 size)
{
	UINT32 i, j, is_spread = 0;
	list <ADDRINT>::iterator addr_it;
	ADDRINT taint_memory_read = 0, taint_memory_write = 0, taint_memory_ptr = 0;
	ADDRINT register_value = 0;
	REG reg = (REG) 0;
	ins_count++;

	if(ins_count % 1000000 == 0)
	{
		fprintf(f, "[*] %lu\n", ins_count);
		fflush(f);
	}

	if(memop0_type == 1) find_tainted_data(memop0);
	if(memop1_type == 1) find_tainted_data(memop1);

	for( i = 0; i < rregs_count; i++ ) /* каждый из читаемых регистров */
	{
		/* содержание в регистре помеченных данных */
		if( check_reg_taint( rregs[i], threadid ) ) /* проверить - не помечен ли регистр */
		{
			is_spread = 1;
			if( ( reg = get_full_reg(rregs[i]) ) != 0 )
				register_value = PIN_GetContextReg(ctx, reg);
			break;
		}
	}

	/* прямое обращение к памяти на чтение */
	if( mems_count != 0 && (memop0_type == 1 || memop1_type == 1) && !is_spread ) /* если есть читаемые операнды памяти и не было найдено распространение */
	{
		for( addr_it = tainted_addrs.begin(); addr_it != tainted_addrs.end(); addr_it++ )
		{
			if( memop0_type == 1 && *addr_it == memop0 )  /* совпадает ли 1 операнд памяти с помеченной памятью */
			{
				taint_memory_read = memop0;
				is_spread = 1; 	/* обнаружено распространение памяти */
				offset = tainted_offsets[memop0];
				break;
			}
			if( memop1_type == 1 && *addr_it == memop1 ) 	/* совпадает ли 2 операнд памяти с помеченной памятью */
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
		/* прямое обращение к памяти на запись */
		if( mems_count != 0 && (memop0_type == 2 || memop1_type == 2) ) /* если есть записываемый операнд памяти */
		{
			if(memop0_type == 2)
			{
				for(i = 0; i < size; i++)
				{
					add_mem_taint( memop0+i ); /* пометить записываемый 1 операнд памяти */
					tainted_offsets[memop0+i] = offset+i;
				}
				taint_memory_write = memop0;
			}
			if(memop1_type == 2)
			{
				for(i = 0; i < size; i++)
				{
					add_mem_taint( memop1+i ); /* пометить записываемый 2 операнд памяти */
					tainted_offsets[memop1+i] = offset+i;
				}
				taint_memory_write = memop1;
			}
		}
		/* запись регистра */
		for( j = 0; j < wregs_count; j++ )  /* каждый из записываемых регистров */
		{
			add_reg_taint( wregs[j], threadid );  /* пометить записываемый регистр */
		}
	}
	else  /* если распространение не было найдено */
	{
		for( i = 0; i < wregs_count; i++ ) 	/* каждый из записываемых регистров */
			del_reg_taint( wregs[i], threadid );
		
		if(memop0_type == 2)
			del_mem_taint( memop0 );
		if(memop1_type == 2)
			del_mem_taint( memop1 );
		
	}

	if(memop0_type)
		save_page(memop0);
	if(memop1_type)
		save_page(memop1);

	if(is_spread || taint_memory_ptr)
		if( (eip >= low_boundary && eip < high_boundary) || (low_boundary == 0 && high_boundary == 0) )
		{
			concolic(threadid, eip, ctx, opcode, rregs_count, rregs, wregs_count, wregs, mems_count, memop0_type, memop0, memop1_type, memop1, size);
			for(i = 0; i < size; i++)
			{
				track_operations(opcode, offset+i);
			}
			fprintf(f, "%s " HEX_FMT ":%u:%lu:", get_module_name(eip), eip - get_module_base(eip), threadid, ins_count);
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
			if(taint_memory_ptr)
			{
				switch(size)
				{
					case 8:
						fprintf( f, " %s:*" HEX_FMT " = %08lX", get_reg_name(reg).c_str(), taint_memory_ptr, *((unsigned long int *)taint_memory_ptr) );
						break;
					case 4:
						fprintf( f, " %s:*" HEX_FMT " = %08X", get_reg_name(reg).c_str(), taint_memory_ptr, *((unsigned int *)taint_memory_ptr) );
						break;
					case 2:
						fprintf( f, " %s:*" HEX_FMT " = %04X", get_reg_name(reg).c_str(), taint_memory_ptr, *((unsigned short *)taint_memory_ptr) );
						break;
					case 1:
						fprintf( f, " %s:*" HEX_FMT " = %02X", get_reg_name(reg).c_str(), taint_memory_ptr, *((unsigned char *)taint_memory_ptr) );
						break;
				}
				telescope( *((int *)taint_memory_ptr), 1 );
			}
			else if(reg)
				fprintf( f, " %s=" HEX_FMT2 ";", get_reg_name(reg).c_str(), register_value );

			fprintf(f, " [0x%x]\n", offset);
			fflush(f);
		}
}


void ins_instrument(INS ins, VOID * v)
{
	REG *rregs, *wregs;
	int rregs_count = 0, wregs_count = 0;
	int i, mems_count = 0;
	ADDRINT eip;
	rregs_count = INS_MaxNumRRegs(ins);
	wregs_count = INS_MaxNumWRegs(ins);
	mems_count = INS_MemoryOperandCount(ins);
	eip = INS_Address(ins);
	rregs = (REG *) malloc( rregs_count * sizeof(REG) );
	wregs = (REG *) malloc( wregs_count * sizeof(REG) );

	if( rregs_count == -1 || wregs_count == -1 || mems_count == -1 )
	{
		fprintf(f, "[!] error " HEX_FMT "\n", eip);
		fflush(f);
		return;
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
					IARG_UINT32, 0,
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
					IARG_UINT32, INS_MemoryOperandIsWritten(ins, 0) ? 2 : 1,
					IARG_MEMORYOP_EA, 0,
					IARG_UINT32, 0,
					IARG_UINT32, 0,
					IARG_MEMORYREAD_SIZE,
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
					IARG_UINT32, INS_MemoryOperandIsWritten(ins, 0) ? 2 : 1,
					IARG_MEMORYOP_EA, 0,
					IARG_UINT32, INS_MemoryOperandIsWritten(ins, 1) ? 2 : 1,
					IARG_MEMORYOP_EA, 1,
					IARG_MEMORYREAD_SIZE,
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

/*
TODO:
	REG_XMM0
	REG_ST0
*/