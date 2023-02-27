/* See COPYRIGHT for copyright information. */

#include <inc/x86.h>
#include <inc/mmu.h>
#include <inc/error.h>
#include <inc/string.h>
#include <inc/assert.h>
#include <inc/elf.h>

#include <kern/env.h>
#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/monitor.h>
#include <kern/sched.h>
#include <kern/kdebug.h>
#include <kern/macro.h>
#include <kern/traceopt.h>

/* Currently active environment */
struct Env *curenv = NULL;

#ifdef CONFIG_KSPACE
/* All environments */
struct Env env_array[NENV];
struct Env *envs = env_array;
#else
/* All environments */
struct Env *envs = NULL;
#endif


/* Free environment list
 * (linked by Env->env_link) */
static struct Env *env_free_list;

/* NOTE: Should be at least LOGNENV */
#define ENVGENSHIFT 12

static const struct{
    const char* name;
    uintptr_t   addr;
} non_dwarf_kern_functions[] = {
    {"sys_yield", (uintptr_t)sys_yield},
    {"sys_exit", (uintptr_t)sys_exit}
};

const size_t N_NON_DWARF_KERN_FUNCTIONS = sizeof(non_dwarf_kern_functions) / sizeof(non_dwarf_kern_functions[0]);

/* Converts an envid to an env pointer.
 * If checkperm is set, the specified environment must be either the
 * current environment or an immediate child of the current environment.
 *
 * RETURNS
 *     0 on success, -E_BAD_ENV on error.
 *   On success, sets *env_store to the environment.
 *   On error, sets *env_store to NULL. */
int
envid2env(envid_t envid, struct Env **env_store, bool need_check_perm) {
    struct Env *env;

    /* If envid is zero, return the current environment. */
    if (!envid) {
        *env_store = curenv;
        return 0;
    }

    /* Look up the Env structure via the index part of the envid,
     * then check the env_id field in that struct Env
     * to ensure that the envid is not stale
     * (i.e., does not refer to a _previous_ environment
     * that used the same slot in the envs[] array). */
    env = &envs[ENVX(envid)];
    if (env->env_status == ENV_FREE || env->env_id != envid) {
        *env_store = NULL;
        return -E_BAD_ENV;
    }

    /* Check that the calling environment has legitimate permission
     * to manipulate the specified environment.
     * If checkperm is set, the specified environment
     * must be either the current environment
     * or an immediate child of the current environment. */
    if (need_check_perm && env != curenv && env->env_parent_id != curenv->env_id) {
        *env_store = NULL;
        return -E_BAD_ENV;
    }

    *env_store = env;
    return 0;
}

/* Mark all environments in 'envs' as free, set their env_ids to 0,
 * and insert them into the env_free_list.
 * Make sure the environments are in the free list in the same order
 * they are in the envs array (i.e., so that the first call to
 * env_alloc() returns envs[0]).
 */
void
env_init(void) {

    /* Set up envs array */

    // LAB 3: Your code here

    for(int n_env = 0; n_env < NENV; n_env++){
        envs[n_env].env_link        = envs + n_env + 1;
        envs[n_env].env_id          = n_env;
        //envs[n_env].env_parent_id   = n_env + 1;
        envs[n_env].env_type        = ENV_TYPE_KERNEL;
        envs[n_env].env_status      = ENV_FREE;
        envs[n_env].env_runs        = 0;
        envs[n_env].binary          = NULL;
    }

    envs[NENV - 1].env_link = NULL;
    env_free_list = envs;
    
    curenv = NULL;

    return;
}

/* Allocates and initializes a new environment.
 * On success, the new environment is stored in *newenv_store.
 *
 * Returns
 *     0 on success, < 0 on failure.
 * Errors
 *    -E_NO_FREE_ENV if all NENVS environments are allocated
 *    -E_NO_MEM on memory exhaustion
 */
int
env_alloc(struct Env **newenv_store, envid_t parent_id, enum EnvType type) {

    struct Env *env;
    if (!(env = env_free_list))
        return -E_NO_FREE_ENV;

    /* Generate an env_id for this environment */
    int32_t generation = (env->env_id + (1 << ENVGENSHIFT)) & ~(NENV - 1);
    /* Don't create a negative env_id */
    if (generation <= 0) generation = 1 << ENVGENSHIFT;
    env->env_id = generation | (env - envs);

    /* Set the basic status variables */
    env->env_parent_id = parent_id;
#ifdef CONFIG_KSPACE
    env->env_type = ENV_TYPE_KERNEL;
#else
    env->env_type = type;
#endif
    env->env_status = ENV_RUNNABLE;
    env->env_runs = 0;

    /* Clear out all the saved register st  ate,
     * to prevent the register values
     * of a prior environment inhabiting this Env structure
     * from "leaking" into our new environment */
    memset(&env->env_tf, 0, sizeof(env->env_tf));

    /* Set up appropriate initial values for the segment registers.
     * GD_UD is the user data (KD - kernel data) segment selector in the GDT, and
     * GD_UT is the user text (KT - kernel text) segment selector (see inc/memlayout.h).
     * The low 2 bits of each segment register contains the
     * Requestor Privilege Level (RPL); 3 means user mode, 0 - kernel mode.  When
     * we switch privilege levels, the hardware does various
     * checks involving the RPL and the Descriptor Privilege Level
     * (DPL) stored in the descriptors themselves */

#ifdef CONFIG_KSPACE
    env->env_tf.tf_ds = GD_KD;
    env->env_tf.tf_es = GD_KD;
    env->env_tf.tf_ss = GD_KD;
    env->env_tf.tf_cs = GD_KT;

    // LAB 3: Your code here:
    static uintptr_t stack_top = 0x2000000;

    unsigned long long env_stack_offset = ((env - envs) + 1) * PAGE_SIZE * 2;

    if(!((stack_top - env_stack_offset) > (UTEXT + PAGE_SIZE * 2) && (stack_top - env_stack_offset) < 0x2000000)){
        panic("attempt to initiate memory [%llx - %llx] for proccess %p", stack_top - env_stack_offset, stack_top - env_stack_offset - 2 * PAGE_SIZE, env);
    }

    env->env_tf.tf_rsp = stack_top - env_stack_offset;
#else
    env->env_tf.tf_ds = GD_UD | 3;
    env->env_tf.tf_es = GD_UD | 3;
    env->env_tf.tf_ss = GD_UD | 3;
    env->env_tf.tf_cs = GD_UT | 3;
    env->env_tf.tf_rsp = USER_STACK_TOP;
#endif

    /* For now init trapframe with IF set */
    env->env_tf.tf_rflags = FL_IF;

    /* Commit the allocation */
    env_free_list = env->env_link;
    *newenv_store = env;

    if (trace_envs) cprintf("[%08x] new env %08x\n", curenv ? curenv->env_id : 0, env->env_id);
    return 0;
}

/* Pass the original ELF image to binary/size and bind all the symbols within
 * its loaded address space specified by image_start/image_end.
 * Make sure you understand why you need to check that each binding
 * must be performed within the image_start/image_end range.
 */
static int
bind_functions(struct Env *env, uint8_t *binary, size_t size, uintptr_t image_start, uintptr_t image_end) {
    // LAB 3: Your code here:

    //? why we should give env parameter to bind_function? We already give binary pointer to it
    //? TODO: image_start/image_end meaning?
    /* NOTE: find_function from kdebug.c should be used */

    // parsing symbol table in elf binary

    const struct Elf* header = (const struct Elf*)binary;

    // TODO: checks

    const struct Secthdr* sections_pos = (struct Secthdr*)(binary + header->e_shoff);
    unsigned int n_sections = header->e_shnum;

    const char*       p_strtab = 0;
    struct Elf64_Sym* p_symtab = 0;

    unsigned int n_symbs = 0;

    // TODO: check e_shstrndx != UNDEF(make other checks from man elf)
    const struct Secthdr* p_shstrtab_header = sections_pos + header->e_shstrndx;
    const char* p_shstrtab = (const char*)(binary + p_shstrtab_header->sh_offset);

    uintptr_t bss_init = 0;
    uintptr_t bss_end = 0;

    for (int section_index = 0; section_index < header->e_shnum; section_index++) {
        const struct Secthdr* section_header = sections_pos + section_index;

        if(strcmp(p_shstrtab + section_header->sh_name, ".bss") == 0) {
            bss_init = section_header->sh_addr;
            bss_end = bss_init + section_header->sh_size;
            break;
        }
    }

    if (bss_init == bss_end) return -1;

    for(unsigned int n_section = 0; n_section < n_sections; n_section++){
        const struct Secthdr* cur_sect = sections_pos + n_section;
        
        // sh_name = undef check??
        if(cur_sect->sh_type == ELF_SHT_STRTAB){
            
            const char* sect_name = p_shstrtab + cur_sect->sh_name;
            // TODO: to strncmp
            if(!strcmp(sect_name, ".strtab")){
                p_strtab = (const char*)(binary + cur_sect->sh_offset);
            }
        }
        else if(cur_sect->sh_type == ELF_SHT_SYMTAB){
            const char* sect_name = p_shstrtab + cur_sect->sh_name;
            // TODO: to strncmp
            if(!strcmp(sect_name, ".symtab")){
                p_symtab = (struct Elf64_Sym*)(binary + cur_sect->sh_offset);
                n_symbs = cur_sect->sh_size / sizeof(struct Elf64_Sym);
            }
        }
    }

    if (p_strtab == NULL) return -1;

    // iterating throw symtab
    for(unsigned int n_sym = 0; n_sym < n_symbs; n_sym++){
        struct Elf64_Sym* cur_sym = p_symtab + n_sym;
        
        //? global + weak
        if(ELF_ST_TYPE(cur_sym->st_info) == STT_OBJECT && ELF_ST_BIND(cur_sym->st_info) == STB_GLOBAL){

            if (cur_sym->st_value < bss_init || cur_sym->st_value >= bss_end) {
                continue;
            }

            const char* symb_name = p_strtab + cur_sym->st_name;
            int kern_func_found = 0;
            
            for(unsigned int n_non_dwarf_func = 0; n_non_dwarf_func < N_NON_DWARF_KERN_FUNCTIONS; n_non_dwarf_func++){
                
                if(strcmp(non_dwarf_kern_functions[n_non_dwarf_func].name, symb_name) == 0){
                    kern_func_found = 1;
                    *((uintptr_t*)cur_sym->st_value) = non_dwarf_kern_functions[n_non_dwarf_func].addr;
                    break;
                }
            }
            if(kern_func_found) continue;

            uintptr_t offset = 0;
            if((offset = find_function(symb_name)) != 0){
                *((uintptr_t*)cur_sym->st_value) = offset;
            }
            else{
                *((uintptr_t*)cur_sym->st_value) = 0;
            }
        }
    }

    return 0;
}

/* Set up the initial program binary, stack, and processor flags
 * for a user process.
 * This function is ONLY called during kernel initialization,
 * before running the first environment.
 *
 * This function loads all loadable segments from the ELF binary image
 * into the environment's user memory, starting at the appropriate
 * virtual addresses indicated in the ELF program header.
 * At the same time it clears to zero any portions of these segments
 * that are marked in the program header as being mapped
 * but not actually present in the ELF file - i.e., the program's bss section.
 *
 * All this is very similar to what our boot loader does, except the boot
 * loader also needs to read the code from disk.  Take a look at
 * LoaderPkg/Loader/Bootloader.c to get ideas.
 *
 * Finally, this function maps one page for the program's initial stack.
 *
 * load_icode returns -E_INVALID_EXE if it encounters problems.
 *  - How might load_icode fail?  What might be wrong with the given input?
 *
 * Hints:
 *   Load each program segment into memory
 *   at the address specified in the ELF section header.
 *   You should only load segments with ph->p_type == ELF_PROG_LOAD.
 *   Each segment's address can be found in ph->p_va
 *   and its size in memory can be found in ph->p_memsz.
 *   The ph->p_filesz bytes from the ELF binary, starting at
 *   'binary + ph->p_offset', should be copied to address
 *   ph->p_va.  Any remaining memory bytes should be cleared to zero.
 *   (The ELF header should have ph->p_filesz <= ph->p_memsz.)
 *
 *   All page protection bits should be user read/write for now.
 *   ELF segments are not necessarily page-aligned, but you can
 *   assume for this function that no two segments will touch
 *   the same page.
 *
 *   You must also do something with the program's entry point,
 *   to make sure that the environment starts executing there.
 *   What?  (See env_run() and env_pop_tf() below.) */
static int
load_icode(struct Env *env, uint8_t *binary, size_t size) {
    // LAB 3: Your code here

    // TODO: Set up the initial stack, and processor flags
    const struct Elf* elf_header = (const struct Elf*)binary;

    if(elf_header->e_magic != ELF_MAGIC)                  return -E_INVALID_EXE;
    
    //?
    //if(elf_header->e_elf[?])
    if(elf_header->e_type == ET_NONE)                     return -E_INVALID_EXE;
    if(elf_header->e_ehsize > size)                       return -E_INVALID_EXE;
    if(elf_header->e_phentsize != sizeof(struct Proghdr)) return -E_INVALID_EXE;
    if(elf_header->e_shentsize != sizeof(struct Secthdr)) return -E_INVALID_EXE;

    unsigned long long int program_headers_size = 0;
    if(__builtin_umulll_overflow(sizeof(struct Proghdr), elf_header->e_phnum, &program_headers_size)) return -E_INVALID_EXE;

    unsigned long long int section_headers_size = 0;
    if(__builtin_umulll_overflow(sizeof(struct Secthdr), elf_header->e_shnum, &section_headers_size)) return -E_INVALID_EXE;
    
    if(program_headers_size > size) return -E_INVALID_EXE;
    if(section_headers_size > size) return -E_INVALID_EXE;

    if(elf_header->e_phoff == 0 || elf_header->e_phoff > size) return -E_INVALID_EXE;
    if(elf_header->e_shoff == 0 || elf_header->e_shoff > size) return -E_INVALID_EXE;
    
    const struct Proghdr* prog_headers = (const struct Proghdr*)(binary + elf_header->e_phoff);
    const struct Secthdr* sect_headers = (const struct Secthdr*)(binary + elf_header->e_shoff);

    for(int n_header = 0; n_header < elf_header->e_phnum; n_header++){
        struct Proghdr prog_header = prog_headers[n_header];

        if(prog_header.p_filesz > prog_header.p_memsz) return -E_INVALID_EXE;

        unsigned long long int prog_header_limit_offset = 0;
        if(__builtin_uaddll_overflow(prog_header.p_offset, prog_header.p_filesz, &prog_header_limit_offset)) return -E_INVALID_EXE;
        if(prog_header_limit_offset > size) return -E_INVALID_EXE;
    }

    for(int n_header = 0 ; n_header < elf_header->e_shnum; n_header++){
        struct Secthdr section_header = sect_headers[n_header];

        unsigned long long int sect_header_limit_offset = 0;
        if(__builtin_uaddll_overflow(section_header.sh_offset, section_header.sh_size, &sect_header_limit_offset)) return -E_INVALID_EXE;
        if(sect_header_limit_offset > size) return -E_INVALID_EXE;
    }

    for(int n_header = 0; n_header < elf_header->e_phnum; n_header++){
        struct Proghdr prog_header = prog_headers[n_header];

        if(prog_header.p_type != ELF_PROG_LOAD || prog_header.p_filesz == 0) continue;

        memcpy((void*)prog_header.p_va, binary + prog_header.p_offset, prog_header.p_filesz);

        if(prog_header.p_memsz > prog_header.p_filesz){
            memset((uint8_t*)prog_header.p_va + prog_header.p_filesz, 0, prog_header.p_memsz - prog_header.p_filesz);
        }
        //? p_flags, p_align
    }

    for(int n_header = 0 ; n_header < elf_header->e_shnum; n_header++){
        struct Secthdr section_header = sect_headers[n_header];

        if(section_header.sh_type == ELF_SHT_NULL) continue;

        memcpy((void*)section_header.sh_addr, binary + section_header.sh_offset, section_header.sh_size);
    }

    env->binary        = binary;
    //? why(figure out)
    env->env_tf.tf_rip = elf_header->e_entry;

    bind_functions(env, binary, size, 0, ~sizeof(0));

    return 0;
}

/* Allocates a new env with env_alloc, loads the named elf
 * binary into it with load_icode, and sets its env_type.
 * This function is ONLY called during kernel initialization,
 * before running the first user-mode environment.
 * The new env's parent ID is set to 0.
 */
void
env_create(uint8_t *binary, size_t size, enum EnvType type) {
    // LAB 3: Your code here

    struct Env* new_env = NULL;

    int alloc_res = env_alloc(&new_env, 0, type);
    
    if(alloc_res == -E_NO_FREE_ENV || alloc_res == -E_NO_MEM){
        panic("env_create: %i\n", alloc_res);
    }

    int binary_load_res = load_icode(new_env, binary, size);
    if(binary_load_res == -E_INVALID_EXE){
        panic("env_create: %i\n", binary_load_res);
    }

    new_env->env_type = type;
    return;
}

/* Frees env and all memory it uses */
void
env_free(struct Env *env) {

    /* Note the environment's demise. */
    if (trace_envs) cprintf("[%08x] free env %08x\n", curenv ? curenv->env_id : 0, env->env_id);

    /* Return the environment to the free list */
    env->env_status = ENV_FREE;
    env->env_link = env_free_list;
    env_free_list = env;
}

/* Frees environment env
 *
 * If env was the current one, then runs a new environment
 * (and does not return to the caller)
 */
void
env_destroy(struct Env *env) {
    /* If env is currently running on other CPUs, we change its state to
     * ENV_DYING. A zombie environment will be freed the next time
     * it traps to the kernel. */

    // LAB 3: Your code here

    env_free(env);

    sched_yield();
}

#ifdef CONFIG_KSPACE
void
csys_exit(void) {
    if (!curenv) panic("curenv = NULL");
    env_destroy(curenv);
}

void
csys_yield(struct Trapframe *tf) {
    memcpy(&curenv->env_tf, tf, sizeof(struct Trapframe));
    sched_yield();
}
#endif

/* Restores the register values in the Trapframe with the 'ret' instruction.
 * This exits the kernel and starts executing some environment's code.
 *
 * This function does not return.
 */

_Noreturn void
env_pop_tf(struct Trapframe *tf) {
    asm volatile(
            "movq %0, %%rsp\n"
            "movq 0(%%rsp), %%r15\n"
            "movq 8(%%rsp), %%r14\n"
            "movq 16(%%rsp), %%r13\n"
            "movq 24(%%rsp), %%r12\n"
            "movq 32(%%rsp), %%r11\n"
            "movq 40(%%rsp), %%r10\n"
            "movq 48(%%rsp), %%r9\n"
            "movq 56(%%rsp), %%r8\n"
            "movq 64(%%rsp), %%rsi\n"
            "movq 72(%%rsp), %%rdi\n"
            "movq 80(%%rsp), %%rbp\n"
            "movq 88(%%rsp), %%rdx\n"
            "movq 96(%%rsp), %%rcx\n"
            "movq 104(%%rsp), %%rbx\n"
            "movq 112(%%rsp), %%rax\n"
            "movw 120(%%rsp), %%es\n"
            "movw 128(%%rsp), %%ds\n"
            "addq $152,%%rsp\n" /* skip tf_trapno and tf_errcode */
            "iretq" ::"g"(tf)
            : "memory");

    /* Mostly to placate the compiler */
    panic("Reached unrecheble\n");
}

/* Context switch from curenv to env.
 * This function does not return.
 *
 * Step 1: If this is a context switch (a new environment is running):
 *       1. Set the current environment (if any) back to
 *          ENV_RUNNABLE if it is ENV_RUNNING (think about
 *          what other states it can be in),
 *       2. Set 'curenv' to the new environment,
 *       3. Set its status to ENV_RUNNING,
 *       4. Update its 'env_runs' counter,
 * Step 2: Use env_pop_tf() to restore the environment's
 *       registers and starting execution of process.

 * Hints:
 *    If this is the first call to env_run, curenv is NULL.
 *
 *    This function loads the new environment's state from
 *    env->env_tf.  Go back through the code you wrote above
 *    and make sure you have set the relevant parts of
 *    env->env_tf to sensible values.
 */
_Noreturn void
env_run(struct Env *env) {
    assert(env);

    if (trace_envs_more) {
        const char *state[] = {"FREE", "DYING", "RUNNABLE", "RUNNING", "NOT_RUNNABLE"};
        if (curenv) cprintf("[%08X] env stopped: %s\n", curenv->env_id, state[curenv->env_status]);
        cprintf("[%08X] env started: %s\n", env->env_id, state[env->env_status]);
    }

    // LAB 3: Your code here

    if(curenv != NULL){
        if(curenv->env_status == ENV_RUNNING){
            curenv->env_status = ENV_RUNNABLE;
        }
        // TODO: env_dying handling
    }
    
    curenv = env;
    curenv->env_status = ENV_RUNNING;
    curenv->env_runs++;
    
    env_pop_tf(&(curenv->env_tf));

    while(1) {}
}
