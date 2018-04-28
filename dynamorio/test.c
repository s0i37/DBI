/* Code Manipulation API Sample:
 * empty.c
 *
 * Serves as an example of an empty client that does nothing but
 * register for the exit event.
 */

#include "dr_api.h"
#include "dr_ir_instr.h"
#include "drmgr.h"

uint bb_count;
char buf[100] = {0};

static void event_exit(void);
static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst,
                      bool for_trace, bool translating, void *user_data);

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    bb_count = 0;
    dr_set_client_name("DynamoRIO Sample Client 'empty'", "http://dynamorio.org/issues");
    disassemble_set_syntax(DR_DISASM_INTEL);
    drmgr_init();
    drmgr_register_bb_instrumentation_event(NULL, event_app_instruction, NULL);
    dr_register_exit_event(event_exit);
}

static void
event_exit(void)
{
    /* empty client */
    printf("bb = %u\n", bb_count);
}

static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst,
                      bool for_trace, bool translating, void *user_data)
{
	instr_t *instr;

	if (!drmgr_is_first_instr(drcontext, inst))
        return DR_EMIT_DEFAULT;
    //dr_printf( "in dynamorio_basic_block(tag=%lx)\n", dr_fragment_app_pc(tag) );
    //instrlist_disassemble(drcontext, tag, bb, STDOUT);
    bb_count += 1;

    for (instr = instrlist_first_app(bb);
         instr != NULL;
         instr = instr_get_next_app(instr))
    {
        instr_disassemble_to_buffer(drcontext, instr, buf, 100);
        printf("%s\n", buf);
    }

    return DR_EMIT_DEFAULT;
}