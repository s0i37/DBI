#include <pin.H>
#include <stdio.h>
#include <list>
#include <deque>
#include <map>
#include <algorithm>
#include <iostream>

#define VERSION "0.32"

#define ALLOCATE 1
#define FREE !ALLOCATE
#define CHECKED 1
#define UAF 1
#define CHUNK_SIZE 4

#ifdef _WIN64
    #define __win__ 1
#elif _WIN32
    #define __win__ 1
#endif

#if defined(__i386__) || defined(_WIN32)
	#define HEX_FMT "0x%08x"
	#define INT_FMT "%u"
#elif defined(__x86_64__) || defined(_WIN64)
	#define HEX_FMT "0x%08lx"
	#define INT_FMT "%lu"
#endif

struct Heap
{
	ADDRINT base;
	unsigned int size;
	bool status;
	bool check;
};
struct Module
{
	ADDRINT low_addr;
	ADDRINT high_addr;
	string name;
};
map < int, deque<ADDRINT> > _calls;
map < int, bool > enable_tracing;
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
KNOB<string> Knob_outfile(KNOB_MODE_WRITEONCE, "pintool", "outfile", "asan.log", "report file");
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
		printf( "\t+" HEX_FMT " %s\n", *it - get_module_base(*it), get_module_name(*it).c_str() );
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
	enable_tracing[threadid] = false;
	//printf("allocate(): disable_instrumentation\n");
	malloc_size = size;
	malloc_call_addr = eip;
	if(size == 0)
	{
		printf( "[!] allocate(NULL) in +" HEX_FMT " %s\n", eip - get_module_base(eip), get_module_name(eip).c_str());
		print_callstack(threadid);
	}
}

void dotrace_allocate_after(UINT32 threadid, ADDRINT eip, ADDRINT addr)
{
	enable_tracing[threadid] = true;
	if( addr == 0 )
	{
		printf( "[!] allocate(" INT_FMT ") = 0 in +" HEX_FMT " %s\n", malloc_size, malloc_call_addr - get_module_base(malloc_call_addr), get_module_name(eip).c_str());
		print_callstack(threadid);
		return;
	}
	list <struct Heap>::iterator it;
	for( it = heap_list.begin(); it != heap_list.end(); it++ )
		if( it->base == addr )
		{
			if(Knob_debug)
			{
				if( it->status == ALLOCATE )
				{
					printf("[*] reallocate(" INT_FMT ") usable memory " HEX_FMT " in " HEX_FMT "\n", malloc_size, addr, malloc_call_addr);
				}
				else
				{
					printf("[*] allocate(" INT_FMT ") old memory " HEX_FMT " in " HEX_FMT "\n", malloc_size, addr, malloc_call_addr);
				}
			}
			it->size = malloc_size;
			it->status = ALLOCATE;
			it->check = !CHECKED;
			printf("[*] allocate(" INT_FMT ") new memory " HEX_FMT " in " HEX_FMT "\n", malloc_size, addr, malloc_call_addr);
			return;
		}

	struct Heap heap;
	heap.base = addr;
	heap.size = malloc_size;
	heap.status = ALLOCATE;
	heap.check = !CHECKED;
	heap_list.push_front(heap);
}

void dotrace_free_before(UINT32 threadid, ADDRINT eip, ADDRINT addr)
{
	//enable_tracing[threadid] = false;
	list <struct Heap>::iterator it;
	for( it = heap_list.begin(); it != heap_list.end(); it++ )
		if( it->base == addr )
		{
			if( it->status == FREE )
			{
				printf( "[!] double-free " HEX_FMT " in +" HEX_FMT " %s (" INT_FMT ")\n", addr, eip - get_module_base(eip), get_module_name(eip).c_str(), threadid);
				print_callstack(threadid);
			}
			it->status = FREE;
			it->check = !CHECKED;
			break;
		}
}

void dotrace_free_after(UINT32 threadid)
{
	//enable_tracing[threadid] = true;
}


/* prevent: UWC heap */
void dotrace_check(UINT32 threadid, ADDRINT eip, ADDRINT ptr, BOOL is_reg)
{
	ADDRINT addr;
	if(! enable_tracing[threadid] )
		return;
	if(is_reg)
		addr = ptr;
	else /* cmp [local_8h], 0  - указатель на кучу лежит в памяти */
		addr = *(ADDRINT *) ptr;
	list <struct Heap>::iterator it;
	for( it = heap_list.begin(); it != heap_list.end(); it++ )
		if( addr >= it->base && addr <= (it->base + it->size) )
		{
			it->check = CHECKED;
			break;
		}
}

void dotrace_use_mem(UINT32 threadid, ADDRINT eip, ADDRINT addr, CONTEXT *ctx)
{
	if(! enable_tracing[threadid] )
		return;

	list <struct Heap>::iterator it;
	for( it = heap_list.begin(); it != heap_list.end(); it++ )
		if( (addr >= it->base - CHUNK_SIZE && addr < it->base) || (addr > it->base + it->size && addr <= it->base + it->size + CHUNK_SIZE) )
		{
			printf( "[!] OOB heap " HEX_FMT " (chunk " HEX_FMT ") in +" HEX_FMT " %s\n", addr, it->base, eip - get_module_base(eip), get_module_name(eip).c_str());
			print_callstack(threadid);
		}

	for( it = heap_list.begin(); it != heap_list.end(); it++ )
		if( addr >= it->base && addr <= it->base + it->size )
		{
			if( it->status == FREE )
			{
				if(eip >= low_boundary && eip <= high_boundary)
				{
					printf( "[!] UAF " HEX_FMT " in +" HEX_FMT " %s\n", addr, eip - get_module_base(eip), get_module_name(eip).c_str());
					print_callstack(threadid);
				}
			}
			else if( it->check != CHECKED )
			{
				if(eip >= low_boundary && eip <= high_boundary)
				{
					printf( "[!] UWC " HEX_FMT " in +" HEX_FMT " %s\n", addr, eip - get_module_base(eip), get_module_name(eip).c_str());
					print_callstack(threadid);
				}
			}
			
			/* don't remind about this again */
			it->check = CHECKED;
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
		        ins, IPOINT_BEFORE, (AFUNPTR)dotrace_check,
		        IARG_UINT32, PIN_ThreadId(),
		        IARG_INST_PTR,
		        IARG_MEMORYOP_EA, 0,
		        IARG_UINT32, 0, /* is_reg=0 */
		        IARG_END);
		/* cmp reg1, ... */
		else if( INS_OperandIsReg(ins, 0) )
			INS_InsertCall(
		        ins, IPOINT_BEFORE, (AFUNPTR)dotrace_check,
		        IARG_UINT32, PIN_ThreadId(),
		        IARG_INST_PTR,
		        IARG_REG_VALUE, INS_OperandReg(ins, 0),
		        IARG_UINT32, 1, /* is_reg=1 */
		        IARG_END);
	}
	/* test ... */
	else if( INS_Opcode(ins) == XED_ICLASS_TEST )
	{
		/* test [mem1], ... */
		if( INS_OperandIsMemory(ins, 0) )
			INS_InsertCall(
		        ins, IPOINT_BEFORE, (AFUNPTR)dotrace_check,
		        IARG_UINT32, PIN_ThreadId(),
		        IARG_INST_PTR,
		        IARG_MEMORYOP_EA, 0,
		        IARG_UINT32, 0, /* is_reg=0 */
		        IARG_END);
		/* test reg1, ... */
		else if( INS_OperandIsReg(ins, 0) )
		    INS_InsertCall(
		        ins, IPOINT_BEFORE, (AFUNPTR)dotrace_check,
		        IARG_UINT32, PIN_ThreadId(),
		        IARG_INST_PTR,
		        IARG_REG_VALUE, INS_OperandReg(ins, 0),
		        IARG_UINT32, 1, /* is_reg=1 */
		        IARG_END);
	}

	/* instr ..., [mem1] */
	if( INS_MemoryOperandCount(ins) )
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
	//SEC sec;
	//RTN rtn;
	if( need_module && strcasestr( IMG_Name(img).c_str(), need_module ) )
	{
		if(Knob_debug)
			printf( "[+] module " HEX_FMT " " HEX_FMT " %s\n", IMG_LowAddress(img), IMG_HighAddress(img), IMG_Name(img).c_str() );
		low_boundary = IMG_LowAddress(img);
		high_boundary = IMG_HighAddress(img);
	}
	else if(Knob_debug)
		printf( "[*] module " HEX_FMT " " HEX_FMT " %s\n", IMG_LowAddress(img), IMG_HighAddress(img), IMG_Name(img).c_str() );
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
			if(Knob_debug)
				printf( "[+] function %s %s\n", IMG_Name(img).c_str(), RTN_Name(allocate).c_str() );
			fflush(f);
			RTN_Close(allocate);
		}
		if( _free.is_valid() )
		{
			free_ptr = RTN_Address(_free);
			RTN_Open(_free);
			RTN_InsertCall(_free, IPOINT_BEFORE, (AFUNPTR)dotrace_free_before, IARG_UINT32, PIN_ThreadId(), IARG_INST_PTR, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_END);
			RTN_InsertCall(_free, IPOINT_AFTER, (AFUNPTR)dotrace_free_after, IARG_UINT32, PIN_ThreadId(), IARG_END);
			if(Knob_debug)
				printf( "[+] function %s %s\n", IMG_Name(img).c_str(), RTN_Name(_free).c_str() );
			fflush(f);
			RTN_Close(_free);
		}
	#elif __linux__

		if( strcasestr( "libc.so.6", IMG_Name(img).c_str() ) != 0 )
			return;

		RTN allocate = RTN_FindByName(img, "malloc");	/* void *malloc(size_t size); 	*/
		RTN _free = RTN_FindByName(img, "free");		/* void free(void *ptr); 		*/
		/* PIN всё равно подставляет __libc_malloc() и cfree() - это более низкоуровневые вызовы*/

		if( allocate.is_valid()  )
		{
			allocate_ptr = RTN_Address(allocate);
			RTN_Open(allocate);
			RTN_InsertCall(allocate, IPOINT_BEFORE, (AFUNPTR)dotrace_allocate_before, IARG_UINT32, PIN_ThreadId(), IARG_INST_PTR, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
			RTN_InsertCall(allocate, IPOINT_AFTER, (AFUNPTR)dotrace_allocate_after, IARG_UINT32, PIN_ThreadId(), IARG_INST_PTR, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
			if(Knob_debug)
				printf( "[+] function %s %s\n", IMG_Name(img).c_str(), RTN_Name(allocate).c_str() );
			fflush(f);
			RTN_Close(allocate);
		}
		if( _free.is_valid()  )
		{
			free_ptr = RTN_Address(_free);
			RTN_Open(_free);
			RTN_InsertCall(_free, IPOINT_BEFORE, (AFUNPTR)dotrace_free_before, IARG_UINT32, PIN_ThreadId(), IARG_INST_PTR, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
			//RTN_InsertCall(_free, IPOINT_AFTER, (AFUNPTR)dotrace_free_after, IARG_UINT32, PIN_ThreadId(), IARG_END);
			/* dotrace_free_after() не срабатывает. Требуется ограничить трассировку внутри free() */
			if(Knob_debug)
				printf( "[+] function %s %s\n", IMG_Name(img).c_str(), RTN_Name(_free).c_str() );
			fflush(f);
			RTN_Close(_free);
		}
	#endif

	/*for( sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec) )
		for( rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn) )
		{
			RTN_Open(rtn);
			printf( "[debug] function %s 0x%08lx %lu\n", RTN_Name(rtn).c_str(), RTN_Address(rtn), RTN_Range(rtn) );
			RTN_Close(rtn);
		}*/
}

void summary(void)
{
	list <struct Heap>::iterator it;
	for(it = heap_list.begin(); it != heap_list.end(); it++)
		if( it->status == ALLOCATE )
		{
			if( it->check != CHECKED )
				printf( "[!] memory leak (no checked): " HEX_FMT "\n", it->base );
			else
				printf( "[!] memory leak " HEX_FMT "\n", it->base );
			fflush(f);
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
  printf( "[x] internal_exception in " HEX_FMT "\n", PIN_GetPhysicalContextReg(pPhysCtxt, REG_INST_PTR) );
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

/*
Implemented non-crashable checks:
	+UWC 			(сразу по возвращению из malloc())
	+UAF 			(сразу по возвращению из free())
	+DoubleFree 	(внутри free(), но не той - поэтому не проводится проверка где нарушение)

TODO non-crashable checks:
	-OOB heap 		(ложные срабатывания внутри free(), инструментацию на время free() нужно как то ограничивать)
	-UMR stack/heap
	-UAR
	-IoF
*/

/*
проблема в следующем:
1)	pin инструментирует не free() вызов а cfree()!
	Он находится глубже и в момент вызова не срабатывает условие:
	eip >= low_boundary && eip <= high_boundary
	так как оно накладывается на исполняемый модуль а не на библиотеки. Решение - убирать проверки low_boundary/high_boundary где можно
2)	RTN_InsertCall(_free, IPOINT_AFTER, (AFUNPTR)dotrace_free_after) не срабатывает
	стало быть нет возможности заморозить asan внутри cfree() и, пометив память как освобождённую,
	произойдёт масса false positive внутри libc.so.
*/