#include <pin.H>
#include <stdio.h>
#include <list>
#include <map>

#define VERSION "0.34"

list <ADDRINT> pages;
list <ADDRINT> tainted_addrs;
map <int, list <REG>> tainted_regs;

const char *need_module;
ADDRINT low_boundary;
ADDRINT high_boundary;
FILE *f;
unsigned long int ins_count = 0;

KNOB<BOOL> Knob_debug(KNOB_MODE_WRITEONCE,  "pintool", "debug", "0", "Enable debug mode");
KNOB<string> Knob_outfile(KNOB_MODE_WRITEONCE,  "pintool", "outfile", "taint.txt", "Output file");
KNOB<ADDRINT> Knob_from(KNOB_MODE_WRITEONCE, "pintool", "from", "0", "start address (absolute) for taint");
KNOB<ADDRINT> Knob_to(KNOB_MODE_WRITEONCE, "pintool", "to", "0", "stop address (absolute) for taint");
KNOB<string> Knob_module(KNOB_MODE_WRITEONCE,  "pintool", "module", "", "taint this module");

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
	for( it = pages.begin(); it != pages.end(); it++ )
		if( (addr & 0xfffff000) == *it )
			return;
	pages.push_back( addr & 0xfffff000 );
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
		case REG_EAX:
		case REG_AX:
		case REG_AH:
		case REG_AL:
			return REG_EAX;

		case REG_ECX:
		case REG_CX:
		case REG_CH:
		case REG_CL:
			return REG_ECX;

		case REG_EDX:
		case REG_DX:
		case REG_DH:
		case REG_DL:
			return REG_EDX;

		case REG_EBX:
		case REG_BX:
		case REG_BH:
		case REG_BL:
			return REG_EBX;

		case REG_EDI:
		case REG_DI:
			return REG_EDI;

		case REG_ESI:
		case REG_SI:
			return REG_ESI;

		default:
			return (REG) 0;
	}
}

string get_reg_name(REG reg)
{
	switch(reg)
	{
		case REG_EAX:
			return "EAX";
		case REG_AX:
			return "AX";
		case REG_AH:
			return "AH";
		case REG_AL:
			return "AL";

		case REG_ECX:
			return "ECX";
		case REG_CX:
			return "CX";
		case REG_CH:
			return "CH";
		case REG_CL:
			return "CL";

		case REG_EDX:
			return "EDX";
		case REG_DX:
			return "DX";
		case REG_DH:
			return "DH";
		case REG_DL:
			return "DL";

		case REG_EBX:
			return "EBX";
		case REG_BX:
			return "BX";
		case REG_BH:
			return "BH";
		case REG_BL:
			return "BL";

		case REG_EDI:
			return "EDI";
		case REG_DI:
			return "DI";

		case REG_ESI:
			return "ESI";
		case REG_SI:
			return "SI";

		default:
			return "UNK";
	}
}

bool add_reg_taint(REG reg, UINT32 threadid)
{
	if( check_reg_taint(reg, threadid) == TRUE )
		return FALSE;

	/*
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
	}
	*/

	switch(reg)
	{
		case REG_EAX:	tainted_regs[threadid].push_front(REG_EAX);
		case REG_AX:	tainted_regs[threadid].push_front(REG_AX);
		case REG_AH:	tainted_regs[threadid].push_front(REG_AH);
		case REG_AL:	tainted_regs[threadid].push_front(REG_AL);
						break;

		case REG_EDX:	tainted_regs[threadid].push_front(REG_EDX);
		case REG_DX:	tainted_regs[threadid].push_front(REG_DX);
		case REG_DH:	tainted_regs[threadid].push_front(REG_DH);
		case REG_DL:	tainted_regs[threadid].push_front(REG_DL);
						break;

		case REG_ECX:	tainted_regs[threadid].push_front(REG_ECX);
		case REG_CX:	tainted_regs[threadid].push_front(REG_CX);
		case REG_CH:	tainted_regs[threadid].push_front(REG_CH);
		case REG_CL:	tainted_regs[threadid].push_front(REG_CL);
						break;

		case REG_EBX:	tainted_regs[threadid].push_front(REG_EBX);
		case REG_BX:	tainted_regs[threadid].push_front(REG_BX);
		case REG_BH:	tainted_regs[threadid].push_front(REG_BH);
		case REG_BL:	tainted_regs[threadid].push_front(REG_BL);
						break;

		case REG_EDI:	tainted_regs[threadid].push_front(REG_EDI);
		case REG_DI:	tainted_regs[threadid].push_front(REG_DI);
						break;

		case REG_ESI:	tainted_regs[threadid].push_front(REG_ESI);
		case REG_SI:	tainted_regs[threadid].push_front(REG_SI);
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

	/*
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
	}
	*/
	switch(reg)
	{
		case REG_EAX:	tainted_regs[threadid].remove(REG_EAX);
		case REG_AX:	tainted_regs[threadid].remove(REG_AX);
		case REG_AH:	tainted_regs[threadid].remove(REG_AH);
		case REG_AL:	tainted_regs[threadid].remove(REG_AL);
						break;

		case REG_EDX:	tainted_regs[threadid].remove(REG_EDX);
		case REG_DX:	tainted_regs[threadid].remove(REG_DX);
		case REG_DH:	tainted_regs[threadid].remove(REG_DH);
		case REG_DL:	tainted_regs[threadid].remove(REG_DL);
						break;

		case REG_ECX:	tainted_regs[threadid].remove(REG_ECX);
		case REG_CX:	tainted_regs[threadid].remove(REG_CX);
		case REG_CH:	tainted_regs[threadid].remove(REG_CH);
		case REG_CL:	tainted_regs[threadid].remove(REG_CL);
						break;

		case REG_EBX:	tainted_regs[threadid].remove(REG_EBX);
		case REG_BX:	tainted_regs[threadid].remove(REG_BX);
		case REG_BH:	tainted_regs[threadid].remove(REG_BH);
		case REG_BL:	tainted_regs[threadid].remove(REG_BL);
						break;

		case REG_EDI:	tainted_regs[threadid].remove(REG_EDI);
		case REG_DI:	tainted_regs[threadid].remove(REG_DI);
						break;

		case REG_ESI:	tainted_regs[threadid].remove(REG_ESI);
		case REG_SI:	tainted_regs[threadid].remove(REG_SI);
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
			fprintf(f, " -> %08lX", *((ADDRINT *)addr) );
			telescope( *((ADDRINT *)addr), deep+1 );
			return;
		}
	fprintf(f, ";");

}


/* catching initial data */
unsigned int buff_len;
ADDRINT buff;
/* WSARecv */
void wsarecv_before(ADDRINT eip, ADDRINT lpBuffers)
{
	if( lpBuffers == 0 )
		return;
	buff_len = ((int *)lpBuffers)[0];
	buff = ((int *)lpBuffers)[1];
}
void wsarecv_after(ADDRINT eip)
{
	unsigned int i;
	for( i = 0; i < buff_len; i++ )
		add_mem_taint( buff + i );
}

/* recv */
void recv_before(ADDRINT eip, ADDRINT lpBuffer, UINT32 buff_size)
{
	buff_len = buff_size;
	buff = lpBuffer;
	fprintf(f, "[*] recv(%d) -> 0x%08lx\n", buff_len, buff );
	fflush(f);
}
void recv_after(ADDRINT eip)
{
	unsigned int i;
	fprintf(f, "[*] *0x%08lx: 0x%08lx\n", buff, *((long unsigned int*)buff) );
	fflush(f);
	for( i = 0; i < buff_len; i++ )
		add_mem_taint( buff + i );
}


void taint(UINT32 threadid, ADDRINT eip, CONTEXT * ctx, int rregs_count, REG * rregs, int wregs_count, REG * wregs, int mems_count, int memop0_type, ADDRINT memop0, int memop1_type, ADDRINT memop1)
{
	int i, j, is_spread = 0;
	list <ADDRINT>::iterator addr_it;
	ADDRINT taint_memory_read = 0, taint_memory_write = 0, taint_memory_ptr = 0;
	ADDRINT register_value = 0;
	REG reg = (REG) 0;

	for( i = 0; i < rregs_count; i++ ) /* каждый из читаемых регистров */
	{
		/* содержание в регистре помеченных данных */
		if( check_reg_taint( rregs[i], threadid ) ) /* проверить - не помечен ли регистр */
		{
			is_spread = 1;
			if( ( reg = get_full_reg( rregs[i] ) ) != 0 )
				register_value = PIN_GetContextReg( ctx, reg );
			break;
		}

		/* содержание в регистре ссылки на помеченные данные (без обращения к памяти) */
		if( ( reg = get_full_reg( rregs[i] ) ) == 0 ) // если регистр общего назначения
			continue;
		if( ( register_value = PIN_GetContextReg( ctx, reg ) ) == 0 ) // если регистр может быть указателем
			continue;
		for( addr_it = tainted_addrs.begin(); addr_it != tainted_addrs.end(); addr_it++ )
			if( register_value == *addr_it ) // если он указывает на помеченную память 
			{
				taint_memory_ptr = register_value;
				break;
			}
		if(taint_memory_ptr)
			break;
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
				break;
			}
			if( memop1_type == 1 && *addr_it == memop1 ) 	/* совпадает ли 2 операнд памяти с помеченной памятью */
			{
				taint_memory_read = memop1;
				is_spread = 1; 	/* обнаружено распространение памяти */
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
				add_mem_taint( memop0 ); /* пометить записываемый 1 операнд памяти */
				taint_memory_write = memop0;
			}
			if(memop1_type == 2)
			{
				add_mem_taint( memop1 ); /* пометить записываемый 2 операнд памяти */
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
			fprintf(f, "0x%08lx:%u:%lu:", eip, threadid, ins_count);
			if(taint_memory_read)
			{
				fprintf( f, " *%08lx -> %08lX", taint_memory_read, *((unsigned long int *)taint_memory_read) );
				telescope( *((int *)taint_memory_read), 1 );
			}
			if(taint_memory_write)
				fprintf( f, " *%08lx <- ;", taint_memory_write );
			if(taint_memory_ptr)
			{
				fprintf( f, " %s:*%08lx = %08lX", get_reg_name(reg).c_str(), taint_memory_ptr, *((unsigned long int *)taint_memory_ptr) );
				telescope( *((int *)taint_memory_ptr), 1 );
			}
			else if(reg && register_value)
				fprintf( f, " %s=%08lX;", get_reg_name(reg).c_str(), register_value );
			fprintf(f, "\n");
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

	ins_count++;

	if( rregs_count == -1 || wregs_count == -1 || mems_count == -1 )
	{
		fprintf(f, "[!] error 0x%08lx\n", eip);
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
					IARG_UINT32, rregs_count,
					IARG_PTR, rregs,
					IARG_UINT32, wregs_count,
					IARG_PTR, wregs,
					IARG_UINT32, 0, 	/* mem_operands count */
					IARG_UINT32, 0, 	/* mem_op0 type */
					IARG_UINT32, 0, 	/* mem_op0 value */
					IARG_UINT32, 0, 	/* mem_op1 type */
					IARG_UINT32, 0, 	/* mem_op1 value */
					IARG_END);
					break;
			case 1: INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) taint,
					IARG_UINT32, PIN_ThreadId(),
					IARG_ADDRINT, eip,
					IARG_CONTEXT,
					IARG_UINT32, rregs_count,
					IARG_PTR, rregs,
					IARG_UINT32, wregs_count,
					IARG_PTR, wregs,
					IARG_UINT32, 1,
					IARG_UINT32, INS_MemoryOperandIsWritten(ins, 0) ? 2 : 1,
					IARG_MEMORYOP_EA, 0,
					IARG_UINT32, 0,
					IARG_UINT32, 0,
					IARG_END);
					break;
			case 2: INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) taint,
					IARG_UINT32, PIN_ThreadId(),
					IARG_ADDRINT, eip,
					IARG_CONTEXT,
					IARG_UINT32, rregs_count,
					IARG_PTR, rregs,
					IARG_UINT32, wregs_count,
					IARG_PTR, wregs,
					IARG_UINT32, 2,
					IARG_UINT32, INS_MemoryOperandIsWritten(ins, 0) ? 2 : 1,
					IARG_MEMORYOP_EA, 0,
					IARG_UINT32, INS_MemoryOperandIsWritten(ins, 1) ? 2 : 1,
					IARG_MEMORYOP_EA, 1,
					IARG_END);
					break;
		}
	}
}

void img_instrument(IMG img, VOID * v)
{
	if(need_module && strcasestr( IMG_Name(img).c_str(), need_module ) )
	{
		fprintf( f, "[+] module instrumented: 0x%08lx 0x%08lx %s\n", IMG_LowAddress(img), IMG_HighAddress(img), IMG_Name(img).c_str() );
		low_boundary = IMG_LowAddress(img);
		high_boundary = IMG_HighAddress(img);
	}
	else
		fprintf( f, "[*] module 0x%08lx 0x%08lx %s\n", IMG_LowAddress(img), IMG_HighAddress(img), IMG_Name(img).c_str() );
	fflush(f);


	/* catch initial data for taint execution */
	RTN wsarecv_ptr = RTN_FindByName(img, "WSARecv");
	if( wsarecv_ptr.is_valid() )
	{
		RTN_Open(wsarecv_ptr);
		RTN_InsertCall(wsarecv_ptr, IPOINT_BEFORE, (AFUNPTR)wsarecv_before, IARG_INST_PTR, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_END);
		RTN_InsertCall(wsarecv_ptr, IPOINT_AFTER, (AFUNPTR)wsarecv_after, IARG_INST_PTR, IARG_END);
		fprintf(f, "[+] wait data %s %s\n", IMG_Name(img).c_str(), RTN_Name(wsarecv_ptr).c_str() );
		RTN_Close(wsarecv_ptr);
	}
}

void fini(INT32 code, VOID *v)
{
	list <ADDRINT>::iterator addr_it;
	fprintf(f, "[+] tainted data still:\n");
	for( addr_it = tainted_addrs.begin(); addr_it != tainted_addrs.end(); addr_it++ )
		fprintf( f, "0x%08lx\n", *addr_it );
	
	fflush(f);
	fclose(f);
}

int main(int argc, char ** argv)
{
	const char *outfile_name;
	if( PIN_Init(argc, argv) )
		return -1;

	PIN_InitSymbols();
	IMG_AddInstrumentFunction(img_instrument, 0);
	INS_AddInstrumentFunction(ins_instrument, 0);
	PIN_AddFiniFunction(fini, 0);
	
	low_boundary = Knob_from.Value();
    high_boundary = Knob_to.Value();
    need_module = Knob_module.Value().c_str();

	outfile_name = Knob_outfile.Value().c_str();
	f = fopen(outfile_name, "w");

	PIN_StartProgram();
	return 0;
}