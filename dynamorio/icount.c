#include "dr_api.h"
#include "drmgr.h" 		/* drmgr_* */
#include <string.h>
#include <stdio.h>


unsigned int bb_count = 0;
unsigned int inst_count = 0;
FILE *f;

static dr_emit_flags_t event_app_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst,
                      bool for_trace, bool translating, void *user_data)
{
	if (!drmgr_is_first_instr(drcontext, inst))
        return DR_EMIT_DEFAULT;

    bb_count += 1;

    for( inst = instrlist_first_app(bb); inst != 0; inst = instr_get_next_app(inst) )
    	inst_count += 1;

    if(bb_count % 1000 == 0)
    {
        fprintf(f, "instr: %d, bb: %d\n", inst_count, bb_count);
        fflush(f);
    }

    return DR_EMIT_DEFAULT;
}


static void event_exit(void)
{
    fprintf(f, "instr: %d, bb: %d\n", inst_count, bb_count);
    fflush(f);
    fclose(f);
    drmgr_exit();
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[])
{
    f = fopen("icount.log", "w");
	dr_register_exit_event(event_exit);

	drmgr_init();
	drmgr_register_bb_instrumentation_event(NULL, event_app_instruction, NULL);
}