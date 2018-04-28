#include "pin.h"
#include <stdio.h>
#include <map>

FILE * f;
map <const char *, unsigned int> dlls;

VOID do_instrument(char * dll)
{
	dlls[dll] = dlls[dll] + 1;
}


VOID img_instrument(IMG img, VOID * v)
{
	dlls.insert( pair <const char *, unsigned int> (IMG_Name(img).c_str(), 0) );
}

VOID rtn_instrument(RTN rtn, VOID *v)
{
	const char * dll = IMG_Name( SEC_Img( RTN_Sec(rtn) ) ).c_str();

	RTN_Open(rtn);
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)do_instrument, IARG_PTR, dll, IARG_END);
	RTN_Close(rtn);
}

VOID fini(INT32 code, VOID *v)
{
	f = fopen("dlls.txt", "w");
	map <const char *, unsigned int>::iterator it;
	for(it = dlls.begin(); it != dlls.end(); it++ )
		fprintf(f, "%s: %d\n", it->first, it->second );
	fclose(f);
}

int main(int argc, char ** argv)
{
	PIN_InitSymbols();
	if( PIN_Init(argc, argv) )
		return -1;
	IMG_AddInstrumentFunction(img_instrument, 0);
	RTN_AddInstrumentFunction(rtn_instrument, 0);
	PIN_AddFiniFunction(fini, 0);
	PIN_StartProgram();
	return 0;
}