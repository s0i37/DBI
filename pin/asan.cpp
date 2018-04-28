#include <pin.H>
#include <stdio.h>
#include <list>
#include <deque>
#include <map>
#include <algorithm>
#include <iostream>

#define VERSION "0.29"

#define ALLOCATE 1
#define FREE !ALLOCATE
#define CHECKED 1
#define UAF 1

#ifdef _WIN64
    #define __win__ 1
#elif _WIN32
    #define __win__ 1
#endif

struct Heap
{
	ADDRINT base;
	unsigned int size;
	bool status;
	bool check;
	bool _is_UAF;
};
struct Module
{
	ADDRINT low_addr;
	ADDRINT high_addr;
	string name;
};
map < int, deque<ADDRINT> > _calls;
map < int, bool > enable_instrumentation;
ADDRINT allocate_ptr;
ADDRINT free_ptr;
unsigned int malloc_size = 0;
ADDRINT malloc_call_addr = 0;
ADDRINT low_boundary;
ADDRINT high_boundary;
const char *need_module;
FILE *f;

list <struct Module> modules;
list <struct Heap> heap_list;

KNOB<BOOL> Knob_debug(KNOB_MODE_WRITEONCE,  "pintool", "debug", "0", "Enable debug mode");
KNOB<string> Knob_outfile(KNOB_MODE_WRITEONCE, "pintool", "outfile", "asan.txt", "report file");
KNOB<string> Knob_module(KNOB_MODE_WRITEONCE,  "pintool", "module", "", "sanitize just this module");


string get_module_name(ADDRINT addr)
{
	list <struct Module>::iterator it;
	for( it = modules.begin(); it != modules.end(); it++ )
		if( addr >= it->low_addr && addr <= it->high_addr )
			return it->name;
	return string("unknown");
}
ADDRINT get_module_base(ADDRINT addr)
{
	list <struct Module>::iterator it;
	for( it = modules.begin(); it != modules.end(); it++ )
		if( addr >= it->low_addr && addr <= it->high_addr )
			return it->low_addr;
	return 0;
}

void print_callstack(UINT32 threadid)
{
	if( _calls.count(threadid) == 0 )
		return;
	deque<ADDRINT>::iterator it = _calls[threadid].end();
	while( it-- != _calls[threadid].begin() )
		fprintf( f, "\t+0x%08lx %s\n", *it - get_module_base(*it), get_module_name(*it).c_str() );
}

void dotrace_CALL(UINT32 threadid, ADDRINT eip)
{
	_calls[threadid].push_back(eip);
}

void dotrace_RET(UINT32 threadid)
{
	if( ! _calls[threadid].empty() )
	{
		_calls[threadid].back();
		_calls[threadid].pop_back();
	}
}

void dotrace_allocate_before(UINT32 threadid, ADDRINT eip, unsigned int size)
{
	enable_instrumentation[threadid] = false;
	printf("allocate(): disable_instrumentation\n");
	malloc_size = size;
	malloc_call_addr = eip;
	if(size == 0)
	{
		if(eip >= low_boundary && eip <= high_boundary)
		{
			fprintf(f, "[!] allocate(NULL) in +0x%08lx %s (%d)\n", eip - get_module_base(eip), get_module_name(eip).c_str(), threadid);
			print_callstack(threadid);
			fflush(f);
		}
	}
}

void dotrace_allocate_after(UINT32 threadid, ADDRINT eip, ADDRINT addr)
{
	enable_instrumentation[threadid] = true;
	printf("allocate(): enable_instrumentation\n");
	if( addr == 0 )
	{
		if(eip >= low_boundary && eip <= high_boundary)
		{
			fprintf(f, "[!] allocate(%d) = 0 in +0x%08lx %s (%d)\n", malloc_size, malloc_call_addr - get_module_base(malloc_call_addr), get_module_name(eip).c_str(), threadid);
			print_callstack(threadid);
			fflush(f);
		}
		return;
	}
	list <struct Heap>::iterator it;
	for( it = heap_list.begin(); it != heap_list.end(); it++ )
		if( it->base == addr )
		{
			printf("[*] reallocate 0x%08lx\n", addr);
			/*if( it->status == ALLOCATE )
			{
				fprintf(f, "[*] reallocate(%d) usable memory 0x%08lx in 0x%08lx\n", malloc_size, addr, malloc_call_addr);
				fflush(f);
			}
			else
			{
				fprintf(f, "[*] allocate(%d) again memory 0x%08lx in 0x%08lx\n", malloc_size, addr, malloc_call_addr);
				fflush(f);
			}*/
			it->size = malloc_size;
			it->status = ALLOCATE;
			it->check = !CHECKED;
			return;
		}

	struct Heap heap;
	heap.base = addr;
	heap.size = malloc_size;
	heap.status = ALLOCATE;
	heap.check = !CHECKED;
	heap._is_UAF = !UAF;
	heap_list.push_front(heap);
	printf("[*] allocate 0x%08lx\n", addr);
}

void dotrace_free_before(UINT32 threadid, ADDRINT eip, ADDRINT addr)
{
	//enable_instrumentation[threadid] = false;
	list <struct Heap>::iterator it;
	for( it = heap_list.begin(); it != heap_list.end(); it++ )
		if( it->base == addr )
		{
			if( it->status == FREE )
			{
				if(eip >= low_boundary && eip <= high_boundary)
				{
					fprintf(f, "[!] double free() memory 0x%08lx in +0x%08lx %s (%d)\n", addr, eip - get_module_base(eip), get_module_name(eip).c_str(), threadid);
					print_callstack(threadid);
					fflush(f);
				}
			}
			else
			{
				it->status = FREE;
				it->check = !CHECKED;
			}
			break;
		}

	if(eip >= low_boundary && eip <= high_boundary)
	{
		fprintf(f, "[!] free() unusable memory 0x%08lx in +0x%08lx %s (%d)\n", addr, eip - get_module_base(eip), get_module_name(eip).c_str(), threadid);
		print_callstack(threadid);
		fflush(f);
	}
}
void dotrace_free_after(UINT32 threadid)
{
	//enable_instrumentation[threadid] = true;
}

void dotrace_check_reg(UINT32 threadid, ADDRINT eip, ADDRINT reg)
{
	if(! enable_instrumentation[threadid] )
		return;
	ADDRINT addr = reg;
	list <struct Heap>::iterator it;
	for( it = heap_list.begin(); it != heap_list.end(); it++ )
		if( addr >= it->base && addr <= (it->base + it->size) )
		{
			if( it->status == FREE && it->_is_UAF != UAF )
			{
				if(eip >= low_boundary && eip <= high_boundary)
				{
					fprintf(f, "[!] UAF memory 0x%08lx in +0x%08lx %s (%d)\n", addr, eip - get_module_base(eip), get_module_name(eip).c_str(), threadid);
					print_callstack(threadid);
					fflush(f);
				}
				it->_is_UAF = UAF;
			}
			it->check = CHECKED;
			break;
		}
}

void dotrace_check_mem(UINT32 threadid, ADDRINT eip, ADDRINT mem)
{
	if(! enable_instrumentation[threadid] )
		return;
	/* cmd [local_8h], 0  - указатель на кучу лежит в памяти */
	ADDRINT addr = *(ADDRINT *) mem;
	list <struct Heap>::iterator it;
	for( it = heap_list.begin(); it != heap_list.end(); it++ )
		if( addr >= it->base && addr <= (it->base + it->size) )
		{
			if( it->status == FREE && it->_is_UAF != UAF )
			{
				if(eip >= low_boundary && eip <= high_boundary)
				{
					fprintf(f, "[!] UAF memory 0x%08lx in +0x%08lx %s (%d)\n", addr, eip - get_module_base(eip), get_module_name(eip).c_str(), threadid);
					print_callstack(threadid);
					fflush(f);
				}
				it->_is_UAF = UAF;
			}
			it->check = CHECKED;
			break;
		}
}

void dotrace_use_mem(UINT32 threadid, ADDRINT eip, ADDRINT addr, CONTEXT *ctx)
{
	if(! enable_instrumentation[threadid] )
		return;
	//ADDRINT addr = *(ADDRINT *) mem;
	if( eip >= low_boundary && eip <= high_boundary )
		printf("0x%08lx: 0x%08lx: 0x%08lx RSP=0x%08lx RAX=0x%08lx\n", eip-low_boundary, addr, *(ADDRINT *)addr, PIN_GetContextReg(ctx, REG_STACK_PTR), PIN_GetContextReg(ctx, REG_GAX));
	list <struct Heap>::iterator it;
	for( it = heap_list.begin(); it != heap_list.end(); it++ )
		if( addr >= it->base && addr <= (it->base + it->size) )
		{
			if( it->status == FREE && it->_is_UAF != UAF )
			{
				if(eip >= low_boundary && eip <= high_boundary)
				{
					fprintf(f, "[!] UAF memory 0x%08lx in +0x%08lx %s (%d)\n", addr, eip - get_module_base(eip), get_module_name(eip).c_str(), threadid);
					print_callstack(threadid);
					fflush(f);
				}
				it->_is_UAF = UAF;
			}
			else if( it->check != CHECKED )
			{
				if(eip >= low_boundary && eip <= high_boundary)
				{
					fprintf(f, "[!] UWC memory 0x%08lx in +0x%08lx %s (%d)\n", addr, eip - get_module_base(eip), get_module_name(eip).c_str(), threadid);
					print_callstack(threadid);
					fflush(f);
				}
			}
			if( eip >= low_boundary && eip <= high_boundary )
				printf("found: 0x%08lx size=%d is_checked=%d\n", it->base, it->size, it->check);
			it->check = CHECKED;
			/* заменить флагом что куча уже была проверена */
			break;
		}
}


void ins_instrument(INS ins, VOID * v)
{
	if ( INS_IsCall(ins) )
	{
		INS_InsertCall(
          ins, IPOINT_BEFORE, (AFUNPTR)dotrace_CALL,
          IARG_UINT32, PIN_ThreadId(),
          IARG_INST_PTR,
          IARG_END);
	}
	else if( INS_IsRet(ins) )
	{
		INS_InsertCall(
          ins, IPOINT_BEFORE, (AFUNPTR)dotrace_RET,
          IARG_UINT32, PIN_ThreadId(),
          IARG_END);
	}

	/* cmp ... */
	else if( INS_Opcode(ins) == XED_ICLASS_CMP )
	{
		/* cmp [mem1], ... */
		if( INS_OperandIsMemory(ins, 0) )
		    INS_InsertCall(
		        ins, IPOINT_BEFORE, (AFUNPTR)dotrace_check_mem,
		        IARG_UINT32, PIN_ThreadId(),
		        IARG_INST_PTR,
		        IARG_MEMORYOP_EA, 0,
		        IARG_END);
		/* cmp reg1, ... */
		else if( INS_OperandIsReg(ins, 0) )
			INS_InsertCall(
		        ins, IPOINT_BEFORE, (AFUNPTR)dotrace_check_reg,
		        IARG_UINT32, PIN_ThreadId(),
		        IARG_INST_PTR,
		        IARG_REG_VALUE, INS_OperandReg(ins, 0),
		        IARG_END);
	}
	/* test ... */
	else if( INS_Opcode(ins) == XED_ICLASS_TEST )
	{
		/* test [mem1], ... */
		if( INS_OperandIsMemory(ins, 0) )
			INS_InsertCall(
		        ins, IPOINT_BEFORE, (AFUNPTR)dotrace_check_mem,
		        IARG_UINT32, PIN_ThreadId(),
		        IARG_INST_PTR,
		        IARG_MEMORYOP_EA, 0,
		        IARG_END);
		/* test reg1, ... */
		else if( INS_OperandIsReg(ins, 0) )
		    INS_InsertCall(
		        ins, IPOINT_BEFORE, (AFUNPTR)dotrace_check_reg,
		        IARG_UINT32, PIN_ThreadId(),
		        IARG_INST_PTR,
		        IARG_REG_VALUE, INS_OperandReg(ins, 0),
		        IARG_END);
	}

	/* instr ..., [mem1] */
	else if( INS_MemoryOperandCount(ins) )
	{
		//std::cout << "0x" << std::hex << INS_Address(ins) << ": " << INS_Disassemble(ins) << std::endl;
		if( INS_MemoryOperandIsRead(ins, 0) )
			INS_InsertCall(
		        ins, IPOINT_BEFORE, (AFUNPTR)dotrace_use_mem,
		        IARG_UINT32, PIN_ThreadId(),
		        IARG_INST_PTR,
		        IARG_MEMORYOP_EA, 0,
		        IARG_CONTEXT,
		        IARG_END);
		if( INS_MemoryOperandIsWritten(ins, 0) )
			INS_InsertCall(
		        ins, IPOINT_BEFORE, (AFUNPTR)dotrace_use_mem,
		        IARG_UINT32, PIN_ThreadId(),
		        IARG_INST_PTR,
		        IARG_MEMORYOP_EA, 0,
		        IARG_CONTEXT,
		        IARG_END);
	}
}

void img_instrument(IMG img, VOID * v)
{
	if( need_module && strcasestr( IMG_Name(img).c_str(), need_module ) )
	{
		fprintf( f, "[+] module instrumented: 0x%08lx 0x%08lx %s\n", IMG_LowAddress(img), IMG_HighAddress(img), IMG_Name(img).c_str() );
		low_boundary = IMG_LowAddress(img);
		high_boundary = IMG_HighAddress(img);
	}
	else
		fprintf( f, "[*] module 0x%08lx 0x%08lx %s\n", IMG_LowAddress(img), IMG_HighAddress(img), IMG_Name(img).c_str() );
	struct Module module = { IMG_LowAddress(img), IMG_HighAddress(img), IMG_Name(img) };
	modules.push_front( module );
	fflush(f);

	#ifdef __win__
		RTN allocate = RTN_FindByName(img, "RtlAllocateHeap");	/* NTSYSAPI PVOID RtlAllocateHeap(PVOID HeapHandle,ULONG Flags, SIZE_T Size);		*/
		RTN _free = RTN_FindByName(img, "RtlFreeHeap");			/* NTSYSAPI LOGICAL RtlFreeHeap(PVOID HeapHandle, ULONG Flags, PVOID BaseAddress);	*/

		if( allocate.is_valid() )
		{
			allocate_ptr = RTN_Address(allocate);
			RTN_Open(allocate);
			RTN_InsertCall(allocate, IPOINT_BEFORE, (AFUNPTR)dotrace_allocate_before, IARG_UINT32, PIN_ThreadId(), IARG_INST_PTR, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_END);
			RTN_InsertCall(allocate, IPOINT_AFTER, (AFUNPTR)dotrace_allocate_after, IARG_UINT32, PIN_ThreadId(), IARG_INST_PTR, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
			fprintf( f, "[+] instrumented %s %s\n", IMG_Name(img).c_str(), RTN_Name(allocate).c_str() );
			fflush(f);
			RTN_Close(allocate);
		}
		if( _free.is_valid() )
		{
			free_ptr = RTN_Address(_free);
			RTN_Open(_free);
			RTN_InsertCall(_free, IPOINT_BEFORE, (AFUNPTR)dotrace_free_before, IARG_UINT32, PIN_ThreadId(), IARG_INST_PTR, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_END);
			RTN_InsertCall(_free, IPOINT_AFTER, (AFUNPTR)dotrace_free_after, IARG_UINT32, PIN_ThreadId(), IARG_END);
			fprintf( f, "[+] instrumented %s %s\n", IMG_Name(img).c_str(), RTN_Name(_free).c_str() );
			fflush(f);
			RTN_Close(_free);
		}
	#elif __linux__
		/*
		PIN не может перехватить вызовы malloc() и free(), т.к. сам использует их.
		По всей видимости это наиболее низкоуровневые вызовы.
		Вызовы __libc_malloc() и cfree() находятся в libc.so и их перехватить удается
		*/
		RTN allocate = RTN_FindByName(img, "__libc_malloc");	/* void *malloc(size_t size); 	*/
		RTN _free = RTN_FindByName(img, "cfree");				/* void free(void *ptr); 		*/

		if( allocate.is_valid() && strcmp( "__libc_malloc", RTN_Name(allocate).c_str() ) == 0 )
		{
			allocate_ptr = RTN_Address(allocate);
			RTN_Open(allocate);
			RTN_InsertCall(allocate, IPOINT_BEFORE, (AFUNPTR)dotrace_allocate_before, IARG_UINT32, PIN_ThreadId(), IARG_INST_PTR, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
			RTN_InsertCall(allocate, IPOINT_AFTER, (AFUNPTR)dotrace_allocate_after, IARG_UINT32, PIN_ThreadId(), IARG_INST_PTR, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
			fprintf( f, "[+] instrumented %s %s\n", IMG_Name(img).c_str(), RTN_Name(allocate).c_str() );
			fflush(f);
			RTN_Close(allocate);
		}
		if( _free.is_valid() && strcmp( "cfree", RTN_Name(_free).c_str() ) == 0 )
		{
			free_ptr = RTN_Address(_free);
			RTN_Open(_free);
			RTN_InsertCall(_free, IPOINT_BEFORE, (AFUNPTR)dotrace_free_before, IARG_UINT32, PIN_ThreadId(), IARG_INST_PTR, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
			//RTN_InsertCall(_free, IPOINT_AFTER, (AFUNPTR)dotrace_free_after, IARG_UINT32, PIN_ThreadId(), IARG_END);
			/* dotrace_free_after() не срабатывает. Требуется ограничить трассировку внутри free() */
			fprintf( f, "[+] instrumented %s %s\n", IMG_Name(img).c_str(), RTN_Name(_free).c_str() );
			fflush(f);
			RTN_Close(_free);
		}
	#endif
}

void summary(void)
{
	list <struct Heap>::iterator it;
	for(it = heap_list.begin(); it != heap_list.end(); it++)
		if( it->status == ALLOCATE )
		{
			fprintf( f, "[!] non free() memory 0x%08lx\n", it->base );
			fflush(f);
			if( it->check != CHECKED )
			{
				fprintf( f, "[!] no checked: 0x%08lx\n", it->base );
				fflush(f);
			}
		}
}

void fini(INT32 code, VOID *v)
{
	summary();
	fflush(f);
	fclose(f);
}

EXCEPT_HANDLING_RESULT internal_exception(THREADID tid, EXCEPTION_INFO *pExceptInfo, PHYSICAL_CONTEXT *pPhysCtxt, VOID *v)
{
  printf( "internal_exception in 0x%08lx\n", PIN_GetPhysicalContextReg(pPhysCtxt, REG_INST_PTR) );
  return EHR_HANDLED;
}

int main(int argc, char ** argv)
{
	if( PIN_Init(argc, argv) )
		return -1;

	PIN_InitSymbols();
	IMG_AddInstrumentFunction(img_instrument, 0);
	INS_AddInstrumentFunction(ins_instrument, 0);
	PIN_AddFiniFunction(fini, 0);
	PIN_AddInternalExceptionHandler(internal_exception, 0);

	need_module = Knob_module.Value().c_str();
	f = fopen( Knob_outfile.Value().c_str(), "w" );
	PIN_StartProgram();
	return 0;
}