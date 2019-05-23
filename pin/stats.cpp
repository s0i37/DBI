#include "pin.H"
#include <stdio.h>
#include <map>
#include <list>

#define VERSION "0.12"

FILE * f;
const char * outfile_name;
struct Module
{
	unsigned int id;
	ADDRINT low_addr;
	ADDRINT high_addr;
	string name;
};
unsigned int modules_loaded = 0;
list <struct Module> modules;
map <unsigned int, unsigned int> modules_call;
map <unsigned int, unsigned int> modules_exec;
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

void save_stats()
{
	f = fopen(outfile_name, "w");
	list <struct Module>::iterator module;
	fprintf(f, "module\tcalls\texec\n");
	for( module = modules.begin(); module != modules.end(); module++ )
		fprintf(f, "%s\t%u\t%u\n", module->name.c_str(), modules_call[module->id], modules_exec[module->id]);
	fclose(f);
}

VOID do_exec(ADDRINT addr)
{
	unsigned int module_id;
	if( (module_id = get_module_id(addr)) != 0 )
		modules_exec[module_id]++;

	instructions += 1;
	if(instructions == max_instructions)
	{
		save_stats();
		PIN_Detach();
	}
}

VOID do_call(ADDRINT addr)
{
	unsigned int module_id;
	if( (module_id = get_module_id(addr)) != 0 )
		modules_call[module_id]++;
}


VOID img_instrument(IMG img, VOID * v)
{
	struct Module module = { ++modules_loaded, IMG_LowAddress(img), IMG_HighAddress(img), IMG_Name(img) };
	modules.push_front( module );
	modules_call[modules_loaded] = 0;
	modules_exec[modules_loaded] = 0;
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
	save_stats();
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