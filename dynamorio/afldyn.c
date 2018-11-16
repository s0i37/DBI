#include "dr_api.h"
#include "dr_ir_instr.h"
#include "drmgr.h"

#define VERSION "0.10"

#ifdef _WIN64
    #define __win__ 1
#elif _WIN32
    #define __win__ 1
#endif

#ifdef __linux__
    #include <sys/shm.h>
    #include <sys/wait.h>
    #include <unistd.h>
    #include <limits.h>
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    int afl_sync_fd = -1;
    bool write_to_pipe(char *);
#elif __win__

#endif

#define MAP_SIZE    (1 << 16)

uint bb_count;

unsigned char bitmap[MAP_SIZE];
unsigned char *bitmap_shm = 0;
unsigned int last_id = 0;

static void event_exit(void);
static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst,
                      bool for_trace, bool translating, void *user_data);

bool setup_shm()
{
    char *shm_key_str;
    if (shm_key_str = getenv("__AFL_SHM_ID")) {
        int shm_id, shm_key;
        shm_key = atoi(shm_key_str); 
    
        if( ( shm_id = shmget( (key_t)shm_key, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600 ) ) < 0 )  // try create by key
            shm_id = shmget( (key_t)shm_key, MAP_SIZE, IPC_EXCL | 0600 );  // find by key
        bitmap_shm = (unsigned char *) (shmat(shm_id, 0, 0));
        
        if (bitmap_shm == (void *)(-1)) {
            return false;
        }
    }
    else {
        return false;
    }
    return true;
}

void TrackBranch(unsigned int cur_addr)
{
    unsigned int cur_id = cur_addr;

    if (bitmap_shm != 0){
        bitmap_shm[((cur_id ^ last_id) % MAP_SIZE)]++;
    }
    else {
        bitmap[((cur_id ^ last_id) % MAP_SIZE)]++;
    }
    last_id = cur_id;
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[])
{
    bb_count = 0;
    dr_set_client_name("DynamoRIO Sample Client 'empty'", "http://dynamorio.org/issues");
    disassemble_set_syntax(DR_DISASM_INTEL);
    drmgr_init();
    drmgr_register_bb_instrumentation_event(NULL, event_app_instruction, NULL);
    dr_register_exit_event(event_exit);
}

static void event_exit(void)
{
    /* empty client */
    dr_printf("bb = %u\n", bb_count);
}

static dr_emit_flags_t event_app_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst,
                      bool for_trace, bool translating, void *user_data)
{
    unsigned int id;
    //setup_shm();
	if (!drmgr_is_first_instr(drcontext, inst))
        return DR_EMIT_DEFAULT;
    id = (unsigned int) (((unsigned int) tag) >> 1);
    //TrackBranch(tag);
    dr_printf("BB: 0x%lx\n", tag);
    bb_count += 1;

    return DR_EMIT_DEFAULT;
}