#include <pin.H>
#include <string>
#include <cstdlib>
#include <iostream>
#include <stdio.h>

#define VERSION "0.05"

FILE *outfile;
ADDRINT min_addr = 0;
ADDRINT max_addr = 0;
ADDRINT from_addr = 0;
ADDRINT to_addr = 0;

KNOB<BOOL> Knob_debug(KNOB_MODE_WRITEONCE,  "pintool", "debug", "0", "Enable debug mode");
KNOB<string> Knob_outfile(KNOB_MODE_WRITEONCE,  "pintool", "outfile", "cov.txt", "Output file");
KNOB<ADDRINT> Knob_from(KNOB_MODE_WRITEONCE, "pintool", "from", "0", "start address (relative) for coverage");
KNOB<ADDRINT> Knob_to(KNOB_MODE_WRITEONCE, "pintool", "to", "0", "stop address (relative) for coverage");

inline ADDRINT valid_addr(ADDRINT addr)
{
    if ( addr >= min_addr + from_addr && ( (to_addr && addr <= min_addr + to_addr) || (!to_addr && addr <= max_addr) ) )
        return true;

    return false;
}

VOID TrackBranch(ADDRINT cur_addr)
{
    ADDRINT rel_addr = cur_addr - min_addr;

    if (Knob_debug) {
        std::cout << "\nCURADDR:  0x" << cur_addr << std::endl;
        std::cout << "rel_addr: 0x" << rel_addr << std::endl;
    }

    fprintf(outfile, "0x%08x\n", rel_addr);
    fflush(outfile);    
}

VOID Trace(TRACE trace, VOID *v)
{
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
        {
            // make sure it is in a segment we want to instrument!
            if (valid_addr(INS_Address(ins)))
            {
                if (INS_IsBranch(ins)) {
                    // As per afl-as.c we only care about conditional branches (so no JMP instructions)
                    if (INS_HasFallThrough(ins) || INS_IsCall(ins))
                    {
                        if (Knob_debug) {
                            
                            std::cout << "BRACH: 0x" << std::hex << INS_Address(ins) << ":\t" << INS_Disassemble(ins) << std::endl;
                        }

                        // Instrument the code.
                        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)TrackBranch,
                            IARG_INST_PTR,
                            IARG_END);
                    }
                }
            }
        }
    }
}

VOID entry_point(VOID *ptr)
{
    /*  Much like the original instrumentation from AFL we only want to instrument the segments of code
     *  from the actual application and not the link and PIN setup itself.
     *
     *  Inspired by: http://joxeankoret.com/blog/2012/11/04/a-simple-pin-tool-unpacker-for-the-linux-version-of-skype/
     */

    IMG img = APP_ImgHead();
    for(SEC sec= IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {
        // lets sanity check the exec flag 
        // TODO: the check for .text name might be too much, there could be other executable segments we
        //       need to instrument but maybe not things like the .plt or .fini/init
        // IF this changes, we need to change the code in the instrumentation code, save all the base addresses.

        if (SEC_IsExecutable(sec) && SEC_Name(sec) == ".text")
        {
            ADDRINT sec_addr = SEC_Address(sec);
            UINT64  sec_size = SEC_Size(sec);
            
            if (Knob_debug)
            {
                std::cout << "Name: " << SEC_Name(sec) << std::endl;
                std::cout << "Addr: 0x" << std::hex << sec_addr << std::endl;
                std::cout << "Size: " << sec_size << std::endl << std::endl;
            }

            if (sec_addr != 0)
            {
                ADDRINT high_addr = sec_addr + sec_size;

                if (sec_addr > min_addr || min_addr == 0)
                    min_addr = sec_addr;

                // Now check and set the max_addr.
                if (sec_addr > max_addr || max_addr == 0)
                    max_addr = sec_addr;

                if (high_addr > max_addr)
                    max_addr = high_addr;
            }
        }
    }
    if (Knob_debug)
    {
        std::cout << "min_addr:\t0x" << std::hex << min_addr << std::endl;
        std::cout << "max_addr:\t0x" << std::hex << max_addr << std::endl << std::endl;
    }   
}

void fini(INT32 code, VOID *v)
{
	fflush(outfile);
	fclose(outfile);
}


int main(int argc, char *argv[])
{
    if( PIN_Init(argc, argv) )
        return -1;

    const char *outfile_name = Knob_outfile.Value().c_str();
	outfile = fopen(outfile_name, "w");
    from_addr = Knob_from.Value();
    to_addr = Knob_to.Value();

	TRACE_AddInstrumentFunction(Trace, 0);
	PIN_AddFiniFunction(fini, 0);
	PIN_AddApplicationStartFunction(entry_point, 0);
	PIN_StartProgram();
    return 0;
}