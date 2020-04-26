#include "pin.H"
#include <stdio.h>
#include <map>
#include <list>

using namespace std;

#define VERSION "0.13"

FILE * f;
const char * outfile_name;
struct Module
{
	unsigned int id;
	ADDRINT low_addr;
	ADDRINT high_addr;
	string name;
};
struct Symbol
{
	unsigned int id;
	unsigned int module_id;
	ADDRINT low_addr;
	ADDRINT high_addr;
	string name;
};
unsigned int modules_loaded = 0;
unsigned int symbols_available = 0;
list <struct Module> modules;
list <struct Symbol> symbols;
map <unsigned int, unsigned int> modules_call;
map <unsigned int, unsigned int> modules_exec;
map <unsigned int, unsigned int> symbols_call;
map <unsigned int, unsigned int> symbols_exec;
unsigned int instructions = 0;
unsigned int max_instructions = 0;

KNOB<string> Knob_outfile(KNOB_MODE_WRITEONCE,  "pintool", "outfile", "stats.log", "Output file");
KNOB<ADDRINT> Knob_max_inst(KNOB_MODE_WRITEONCE, "pintool", "max_inst", "0", "maximum count of instructions");

unsigned int get_module_id(ADDRINT addr)
{
	list <struct Module>::iterator it;
	for( it = modules.begin(); it != modules.end(); it++ )
		if( addr >= it->low_addr && addr <= it->high_addr )
			return it->id;
	return 0;
}

unsigned int get_symbol_id(ADDRINT addr)
{
	list <struct Symbol>::iterator it;
	for( it = symbols.begin(); it != symbols.end(); it++ )
		if( addr >= it->low_addr && addr <= it->high_addr )
			return it->id;
	return 0;
}

void modules_stats()
{
	list <struct Module>::iterator module;
	list <unsigned int> calls;

	for(module = modules.begin(); module != modules.end(); module++)
		calls.push_back(modules_call[module->id]);
	calls.sort();

	printf("module\tcalls\texec\n");
	do
	{
		for( module = modules.begin(); module != modules.end(); module++ )
		{
			if(modules_call[module->id] == calls.back())
			{
				printf("0x%08lx \t (%u) %s \t %u \t %u\n",
					module->low_addr, module->id, module->name.c_str(), modules_call[module->id], modules_exec[module->id]);
				break;
			}
		}
		calls.pop_back();
	}
	while(calls.size() != 0);

	for(module = modules.begin(); module != modules.end(); module++)
	{
		modules_call[module->id] = 0;
		modules_exec[module->id] = 0;
	}	
}

void symbols_stats(unsigned int module_id)
{
	unsigned int limit = 20;
	list <struct Symbol>::iterator symbol;
	list <unsigned int> calls;
	list <unsigned int> execs;

	for(symbol = symbols.begin(); symbol != symbols.end(); symbol++)
		if(module_id && symbol->module_id == module_id)
			calls.push_back(symbols_call[symbol->id]);
	calls.sort();

	printf("symbol\tcalls\texec\n");
	do
	{
		for(symbol = symbols.begin(); symbol != symbols.end(); symbol++)
		{
			if(module_id && symbol->module_id == module_id)
			{
				if(symbols_call[symbol->id] == calls.back())
				{
					printf("%s \t %u \t %u\n",
						symbol->name.c_str(), symbols_call[symbol->id], symbols_exec[symbol->id]);
					break;
				}
			}
		}
		calls.pop_back();
		if(--limit == 0)
			break;
	}
	while(calls.size() != 0);

	for(symbol = symbols.begin(); symbol != symbols.end(); symbol++)
	{
		symbols_call[symbol->id] = 0;
		symbols_exec[symbol->id] = 0;
	}	
}

VOID do_exec(ADDRINT addr)
{
	unsigned int module_id;
	//unsigned int symbol_id;
	if( (module_id = get_module_id(addr)) != 0 )
		modules_exec[module_id]++;
	//if( (symbol_id = get_symbol_id(addr)) != 0 )
	//	symbols_exec[symbol_id]++;

	instructions += 1;
	if(instructions == max_instructions)
	{
		modules_stats();
		PIN_Detach();
	}
	if(instructions % 100000 == 0)
	{	
		modules_stats();
		//symbols_stats(8);
	}
}

VOID do_call(ADDRINT addr)
{
	unsigned int module_id;
	unsigned int symbol_id;
	if( (module_id = get_module_id(addr)) != 0 )
		modules_call[module_id]++;
	if( (symbol_id = get_symbol_id(addr)) != 0 )
		symbols_call[symbol_id]++;
}


VOID img_instrument(IMG img, VOID * v)
{
	RTN rtn;
	SEC sec;
	struct Module module = { ++modules_loaded, IMG_LowAddress(img), IMG_HighAddress(img), IMG_Name(img) };
	modules.push_front( module );
	modules_call[modules_loaded] = 0;
	modules_exec[modules_loaded] = 0;

	for( sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec) )
		for( rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn) )
		{
			RTN_Open(rtn);
			struct Symbol symbol = { ++symbols_available, modules_loaded, RTN_Address(rtn), RTN_Address(rtn) + RTN_Range(rtn), RTN_Name(rtn).c_str() };
			symbols.push_front(symbol);
			RTN_Close(rtn);
		}
}

VOID rtn_instrument(RTN rtn, VOID *v)
{
	RTN_Open(rtn);
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)do_call, IARG_ADDRINT, RTN_Address(rtn), IARG_END);
	RTN_Close(rtn);
}

VOID ins_instrument(INS ins, VOID *v)
{
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)do_exec, IARG_ADDRINT, INS_Address(ins), IARG_END);
}


VOID fini(INT32 code, VOID *v)
{
	modules_stats();
}

int main(int argc, char ** argv)
{
	PIN_InitSymbols();
	if( PIN_Init(argc, argv) )
		return -1;

	outfile_name = Knob_outfile.Value().c_str();
	max_instructions = Knob_max_inst.Value();

	IMG_AddInstrumentFunction(img_instrument, 0);
	RTN_AddInstrumentFunction(rtn_instrument, 0);
	INS_AddInstrumentFunction(ins_instrument, 0);
	PIN_AddFiniFunction(fini, 0);
	PIN_StartProgram();
	return 0;
}