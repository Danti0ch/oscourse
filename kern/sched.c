#include <inc/assert.h>
#include <inc/x86.h>
#include <kern/env.h>
#include <kern/monitor.h>


struct Taskstate cpu_ts;
_Noreturn void sched_halt(void);

/* Choose a user environment to run and run it */
_Noreturn void
sched_yield(void) {
    /* Implement simple round-robin scheduling.
     *
     * Search through 'envs' for an ENV_RUNNABLE environment in
     * circular fashion starting just after the env was
     * last running.  Switch to the first such environment found.
     *
     * If no envs are runnable, but the environment previously
     * running is still ENV_RUNNING, it's okay to
     * choose that environment.
     *
     * If there are no runnable environments,
     * simply drop through to the code
     * below to halt the cpu */

    // LAB 3: Your code here:
    
    size_t active_env_ind = NENV;
    if(curenv != NULL){
        active_env_ind = (size_t)(curenv - envs);
    }
    
    const size_t invalid_active_env_id = -1;
    size_t new_active_env_ind = invalid_active_env_id;

    for(size_t n_env = active_env_ind + 1; n_env < NENV; n_env++){
        if(envs[n_env].env_status == ENV_RUNNABLE){
            new_active_env_ind = n_env;
            break;
        }
    }

    if(new_active_env_ind == invalid_active_env_id){
        for(size_t n_env = 0; n_env < active_env_ind; n_env++){
            if(envs[n_env].env_status == ENV_RUNNABLE){
                new_active_env_ind = n_env;
                break;  
            }
        }
    }

    if(new_active_env_ind == invalid_active_env_id){
        if(active_env_ind < NENV && envs[active_env_ind].env_status == ENV_RUNNING ){
            new_active_env_ind = active_env_ind;
        }
    } 
    
    if(new_active_env_ind != invalid_active_env_id){
        env_run(&envs[new_active_env_ind]);
    }

    cprintf("Halt\n");

    /* No runnable environments,
     * so just halt the cpu */
    sched_halt();
}

/* Halt this CPU when there is nothing to do. Wait until the
 * timer interrupt wakes it up. This function never returns */
_Noreturn void
sched_halt(void) {

    /* For debugging and testing purposes, if there are no runnable
     * environments in the system, then drop into the kernel monitor */
    int i;
    for (i = 0; i < NENV; i++)
        if (envs[i].env_status == ENV_RUNNABLE ||
            envs[i].env_status == ENV_RUNNING) break;
    if (i == NENV) {
        cprintf("No runnable environments in the system!\n");
        for (;;) monitor(NULL);
    }

    /* Mark that no environment is running on CPU */
    curenv = NULL;

    /* Reset stack pointer, enable interrupts and then halt */
    asm volatile(
            "movq $0, %%rbp\n"
            "movq %0, %%rsp\n"
            "pushq $0\n"
            "pushq $0\n"
            "sti\n"
            "hlt\n" ::"a"(cpu_ts.ts_rsp0));

    /* Unreachable */
    for (;;)
        ;
}
