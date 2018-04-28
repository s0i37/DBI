#include "pin.h"
#include <stdio.h>

unsigned int exceptionCount;
static CONTEXT savedFromContext;
static CONTEXT savedToContext;
static INT32   savedReason;

void context_change(THREADID threadIndex, 
                        CONTEXT_CHANGE_REASON reason, 
                        const CONTEXT *ctxtFrom,
                        CONTEXT *ctxtTo,
                        INT32 info, 
                        VOID *v)
{

    if(reason == CONTEXT_CHANGE_REASON_EXCEPTION)
    {
        if(exceptionCount++ == 0)
        {
            PIN_SaveContext (ctxtFrom, &savedFromContext);
            PIN_SaveContext (ctxtTo,   &savedToContext);
            savedReason = info;
        }
        printf("See exception %d : info 0x%x from 0x%08x\n", exceptionCount, info,
                 PIN_GetContextReg(ctxtFrom, REG_INST_PTR));
        
        if(exceptionCount == 2)
        {
            // Check that the second exception is the same as the first, at least to a first approximation.
            if (info == savedReason && 
                PIN_GetContextReg(ctxtFrom, REG_INST_PTR) == PIN_GetContextReg(&savedFromContext, REG_INST_PTR))
            {
                printf("Second exception looks like a replay, good!\n");
            }
            else
            {
                printf("Second exception does not look like a replay, BAD!\n");
            }
            exceptionCount = 0;
        }
    }
    else
    	printf("context switch\n");
}

EXCEPT_HANDLING_RESULT internal_exception(THREADID tid, EXCEPTION_INFO *pExceptInfo, PHYSICAL_CONTEXT *pPhysCtxt, VOID *v)
{
  printf( "internal_exception in 0x%08x\n", PIN_GetPhysicalContextReg(pPhysCtxt, REG_INST_PTR) );
  return EHR_HANDLED;
}