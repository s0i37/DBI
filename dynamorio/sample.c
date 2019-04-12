#include "dr_api.h"
#include "drmgr.h" 		/* drmgr_* */
#include "drwrap.h" 	/* drwrap_* */
#include <string.h>


unsigned int bb_count = 0;
unsigned int inst_count = 0;
unsigned char buf[100];

static dr_emit_flags_t event_app_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst,
                      bool for_trace, bool translating, void *user_data)
{
	if (!drmgr_is_first_instr(drcontext, inst))
        return DR_EMIT_DEFAULT;
    dr_printf("BB: 0x%lx\n", tag);
    bb_count += 1;

    instrlist_disassemble(drcontext, tag, bb, STDOUT);
    for( inst = instrlist_first_app(bb); inst != 0; inst = instr_get_next_app(inst) )
    {
    	if( instr_disassemble_to_buffer( drcontext, inst, buf, sizeof(buf) ) )
    		dr_printf("0x%0x: %s\n", instr_get_app_pc(inst), buf);
    	inst_count += 1;
	}

    return DR_EMIT_DEFAULT;
}

static void wrap_pre(void *wrapcxt, OUT void **user_data)
{
    unsigned int size = (unsigned int) drwrap_get_arg(wrapcxt,0);
    dr_fprintf(STDERR, "malloc(%lu)\n", size);
}

static void wrap_post(void *wrapcxt, void *user_data)
{
	dr_fprintf(STDERR, "malloc -> %lu\n", (unsigned int) drwrap_get_retval(wrapcxt));
}

static void module_load_event(void *drcontext, const module_data_t *mod, bool loaded)
{
    app_pc towrap = (app_pc) dr_get_proc_address(mod->handle, "malloc");
    if(towrap != NULL)
        drwrap_wrap(towrap, wrap_pre, wrap_post);
}

static void event_exit(void)
{
    dr_printf("bb: %d, instr: %d\n", bb_count, inst_count);
    drwrap_exit();
    drmgr_exit();
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[])
{
	dr_set_client_name("DynamoRIO Sample Client", "http://dynamorio.org/issues");
	disassemble_set_syntax(DR_DISASM_INTEL);

	/* dr<ext>_register_<somethink>_event() */
	dr_register_exit_event(event_exit);

	drmgr_init();
	drwrap_init();
	drmgr_register_module_load_event(module_load_event);
	drmgr_register_bb_instrumentation_event(NULL, event_app_instruction, NULL);

	memset( buf, 0, sizeof(buf) );
}