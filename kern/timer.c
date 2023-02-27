#include <inc/types.h>
#include <inc/assert.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/stdio.h>
#include <inc/x86.h>
#include <inc/uefi.h>
#include <kern/timer.h>
#include <kern/kclock.h>
#include <kern/picirq.h>
#include <kern/trap.h>
#include <kern/sched.h>
#include <kern/pmap.h>

#define kilo      (1000ULL)
#define Mega      (kilo * kilo)
#define Giga      (kilo * Mega)
#define Tera      (kilo * Giga)
#define Peta      (kilo * Tera)
#define ULONG_MAX ~0UL


#define ACPI_RSDP_SIGNATURE  (*(int64_t*)"RSD PTR ")
#define ACPI_RSDT_SIGNATURE  (*(int32_t*)"RSDT")
#define ACPI_FADT_SIGNATURE  (*(int32_t*)"FACP")

#define RSDT_N_TABLES(rsdt_ptr) (rsdt_ptr->h.Length - sizeof(rsdt_ptr->h) / sizeof(int32_t))

#if LAB <= 6
/* Early variant of memory mapping that does 1:1 aligned area mapping
 * in 2MB pages. You will need to reimplement this code with proper
 * virtual memory mapping in the future. */
void *
mmio_map_region(physaddr_t pa, size_t size) {
    void map_addr_early_boot(uintptr_t addr, uintptr_t addr_phys, size_t sz);
    const physaddr_t base_2mb = 0x200000;
    uintptr_t org = pa;
    size += pa & (base_2mb - 1);
    size += (base_2mb - 1);
    pa &= ~(base_2mb - 1);
    size &= ~(base_2mb - 1);
    map_addr_early_boot(pa, pa, size);
    return (void *)org;
}
void *
mmio_remap_last_region(physaddr_t pa, void *addr, size_t oldsz, size_t newsz) {
    return mmio_map_region(pa, newsz);
}
#endif

struct Timer timertab[MAX_TIMERS];
struct Timer *timer_for_schedule;

struct Timer timer_hpet0 = {
        .timer_name = "hpet0",
        .timer_init = hpet_init,
        .get_cpu_freq = hpet_cpu_frequency,
        .enable_interrupts = hpet_enable_interrupts_tim0,
        .handle_interrupts = hpet_handle_interrupts_tim0,
};

struct Timer timer_hpet1 = {
        .timer_name = "hpet1",
        .timer_init = hpet_init,
        .get_cpu_freq = hpet_cpu_frequency,
        .enable_interrupts = hpet_enable_interrupts_tim1,
        .handle_interrupts = hpet_handle_interrupts_tim1,
};

struct Timer timer_acpipm = {
        .timer_name = "pm",
        .timer_init = acpi_enable,
        .get_cpu_freq = pmtimer_cpu_frequency,
};

void
acpi_enable(void) {
    FADT *fadt = get_fadt();
    outb(fadt->SMI_CommandPort, fadt->AcpiEnable);
    while ((inw(fadt->PM1aControlBlock) & 1) == 0) /* nothing */
        ;
}

// returns 1 if correct, 0 otherwise
int validate_sdt_checksum(ACPISDTHeader* sdt_ptr){

    uint8_t struct_sum = 0;
    for(uint8_t* p_byte = (uint8_t*)sdt_ptr; p_byte < (uint8_t*)(sdt_ptr + sdt_ptr->Length); p_byte++){
        struct_sum += *p_byte;
    }

    return 1;
    //return struct_sum == 0;
}

static void *
acpi_find_table(const char *sign) {
    /*
     * This function performs lookup of ACPI table by its signature
     * and returns valid pointer to the table mapped somewhere.
     *
     * It is a good idea to checksum tables before using them.
     *
     * HINT: Use mmio_map_region/mmio_remap_last_region
     * before accessing table addresses
     * (Why mmio_remap_last_region is requrired?)
     * HINT: RSDP address is stored in uefi_lp->ACPIRoot
     * HINT: You may want to distunguish RSDT/XSDT
     */

    // LAB 5: Your code here

    RSDP* rsdp_ptr = (RSDP*)uefi_lp->ACPIRoot;

    assert(sizeof(ACPI_RSDP_SIGNATURE) == sizeof(int64_t));

    if(*(int64_t*)rsdp_ptr->Signature != ACPI_RSDP_SIGNATURE){
        panic("acpi_find_table: signature of rsdp is invalid\n");
    }

    uint8_t struct_sum = 0;
    //for(uint8_t* p_byte = (uint8_t*)rsdp_ptr; p_byte < (uint8_t*)(rsdp_ptr + sizeof(RSDP)); p_byte++){
        
    //    struct_sum += *p_byte;
    //}
    if(struct_sum != 0){
        panic("acpi_find_table: checksum of rsdp is invalid\n");
    }

    assert((uint64_t)rsdp_ptr->RsdtAddress != (uint64_t)rsdp_ptr->XsdtAddress && "xsdt and rsdt adresses differ");

    //!
    RSDT* rsdt_ptr = (RSDT*)(uintptr_t)rsdp_ptr->RsdtAddress;

    assert(sizeof(ACPI_RSDT_SIGNATURE) == sizeof(int32_t));

    if(*(int32_t*)rsdt_ptr->h.Signature != ACPI_RSDT_SIGNATURE){
        panic("acpi_find_table: signature of rsdt is invalid\n"); 
    }

    if(!(validate_sdt_checksum((ACPISDTHeader*)rsdt_ptr))){
        panic("acpi_find_table: checksum of rsdt is invalid\n");
    }

    int n_tables = RSDT_N_TABLES(rsdt_ptr);
    for(int n_table = 0; n_table < n_tables; n_table++){

        ACPISDTHeader* table_header = (ACPISDTHeader*)(uintptr_t)(rsdt_ptr->PointerToOtherSDT[n_table]);
        if(strncmp(table_header->Signature, sign, 4) == 0){
            return (void*)table_header;
        }
    }

    return NULL;
}

/* Obtain and map FADT ACPI table address. */
FADT *
get_fadt(void) {
    // LAB 5: Your code here
    // (use acpi_find_table)
    // HINT: ACPI table signatures are
    //       not always as their names

    static FADT *kfadt = NULL;
    kfadt = acpi_find_table("FACP");

    if(kfadt == NULL){
        panic("get_fadt: unable to get FADT table");
    }

    if(!validate_sdt_checksum((ACPISDTHeader*)kfadt)){
        panic("get_fadt: signature FADT table is invalid");
    }
    return kfadt;
}

/* Obtain and map RSDP ACPI table address. */
HPET *
get_hpet(void) {
    // LAB 5: Your code here
    // (use acpi_find_table)

    static HPET *khpet = NULL;
    khpet = acpi_find_table("HPET");

    if(khpet == NULL){
        panic("get_hpet: unable to get HPET table");
    }

    if(!validate_sdt_checksum((ACPISDTHeader*)khpet)){
        panic("get_hpet: signature HPET table is invalid");
    }

    if(khpet->hardware_rev_id == 0){
        panic("get_hpet: hardware_rev_id is 0");
    }

    if(khpet->counter_size != 1){
        panic("get_hpet: hpet is not enable to run in 64 mode");
    }

    if(khpet->legacy_replacement != 1){
        panic("get_hpet: hpet doesn't support legacy replacement");
    }
    
    //? vendot id meaning
 
    //if(khpet->minimum_tick)
    return khpet;
}

/* Getting physical HPET timer address from its table. */
HPETRegister *
hpet_register(void) {
    HPET *hpet_timer = get_hpet();
    if (!hpet_timer->address.address) panic("hpet is unavailable\n");

    uintptr_t paddr = hpet_timer->address.address;
    return mmio_map_region(paddr, sizeof(HPETRegister));
}

/* Debug HPET timer state. */
void
hpet_print_struct(void) {
    HPET *hpet = get_hpet();
    assert(hpet != NULL);
    cprintf("signature = %s\n", (hpet->h).Signature);
    cprintf("length = %08x\n", (hpet->h).Length);
    cprintf("revision = %08x\n", (hpet->h).Revision);
    cprintf("checksum = %08x\n", (hpet->h).Checksum);

    cprintf("oem_revision = %08x\n", (hpet->h).OEMRevision);
    cprintf("creator_id = %08x\n", (hpet->h).CreatorID);
    cprintf("creator_revision = %08x\n", (hpet->h).CreatorRevision);

    cprintf("hardware_rev_id = %08x\n", hpet->hardware_rev_id);
    cprintf("comparator_count = %08x\n", hpet->comparator_count);
    cprintf("counter_size = %08x\n", hpet->counter_size);
    cprintf("reserved = %08x\n", hpet->reserved);
    cprintf("legacy_replacement = %08x\n", hpet->legacy_replacement);
    cprintf("pci_vendor_id = %08x\n", hpet->pci_vendor_id);
    cprintf("hpet_number = %08x\n", hpet->hpet_number);
    cprintf("minimum_tick = %08x\n", hpet->minimum_tick);

    cprintf("address_structure:\n");
    cprintf("address_space_id = %08x\n", (hpet->address).address_space_id);
    cprintf("register_bit_width = %08x\n", (hpet->address).register_bit_width);
    cprintf("register_bit_offset = %08x\n", (hpet->address).register_bit_offset);
    cprintf("address = %08lx\n", (unsigned long)(hpet->address).address);
}

static volatile HPETRegister *hpetReg;
/* HPET timer period (in femtoseconds) */
static uint64_t hpetFemto = 0;
/* HPET timer frequency */
static uint64_t hpetFreq = 0;

uint64_t hpet_freq(){
    return hpetFreq;
}


/* HPET timer initialisation */
void
hpet_init() {
    if (hpetReg == NULL) {
        nmi_disable();
        hpetReg = hpet_register();
        uint64_t cap = hpetReg->GCAP_ID;
        hpetFemto = (uintptr_t)(cap >> 32);
        if (!(cap & HPET_LEG_RT_CAP)) panic("HPET has no LegacyReplacement mode");

        /* cprintf("hpetFemto = %llu\n", hpetFemto); */
        hpetFreq = (1 * Peta) / hpetFemto;
        /* cprintf("HPET: Frequency = %d.%03dMHz\n", (uintptr_t)(hpetFreq / Mega), (uintptr_t)(hpetFreq % Mega)); */
        /* Enable ENABLE_CNF bit to enable timer */
        hpetReg->GEN_CONF |= HPET_ENABLE_CNF;
        nmi_enable();
    }
}

/* HPET register contents debugging. */
void
hpet_print_reg(void) {
    cprintf("GCAP_ID = %016lx\n", (unsigned long)hpetReg->GCAP_ID);
    cprintf("GEN_CONF = %016lx\n", (unsigned long)hpetReg->GEN_CONF);
    cprintf("GINTR_STA = %016lx\n", (unsigned long)hpetReg->GINTR_STA);
    cprintf("MAIN_CNT = %016lx\n", (unsigned long)hpetReg->MAIN_CNT);
    cprintf("TIM0_CONF = %016lx\n", (unsigned long)hpetReg->TIM0_CONF);
    cprintf("TIM0_COMP = %016lx\n", (unsigned long)hpetReg->TIM0_COMP);
    cprintf("TIM0_FSB = %016lx\n", (unsigned long)hpetReg->TIM0_FSB);
    cprintf("TIM1_CONF = %016lx\n", (unsigned long)hpetReg->TIM1_CONF);
    cprintf("TIM1_COMP = %016lx\n", (unsigned long)hpetReg->TIM1_COMP);
    cprintf("TIM1_FSB = %016lx\n", (unsigned long)hpetReg->TIM1_FSB);
    cprintf("TIM2_CONF = %016lx\n", (unsigned long)hpetReg->TIM2_CONF);
    cprintf("TIM2_COMP = %016lx\n", (unsigned long)hpetReg->TIM2_COMP);
    cprintf("TIM2_FSB = %016lx\n", (unsigned long)hpetReg->TIM2_FSB);
}

/* HPET main timer counter value. */
uint64_t
hpet_get_main_cnt(void) {
    return hpetReg->MAIN_CNT;
}

/* - Configure HPET timer 0 to trigger every 0.5 seconds on IRQ_TIMER line
 * - Configure HPET timer 1 to trigger every 1.5 seconds on IRQ_CLOCK line
 *
 * HINT To be able to use HPET as PIT replacement consult
 *      LegacyReplacement functionality in HPET spec.
 * HINT Don't forget to unmask interrupt in PIC */
void
hpet_enable_interrupts_tim0(void) {
    // LAB 5: Your code here
    pic_irq_unmask(IRQ_TIMER);

    hpetReg->GEN_CONF |= HPET_ENABLE_CNF;
    hpetReg->GEN_CONF |= HPET_LEG_RT_CNF;
    hpetReg->TIM0_CONF |= HPET_TN_TYPE_CNF;
    hpetReg->TIM0_CONF |= HPET_TN_INT_ENB_CNF;

    hpetReg->GEN_CONF &= ~HPET_ENABLE_CNF;
    hpetReg->MAIN_CNT = 0;
    hpetReg->TIM0_CONF |= HPET_TN_VAL_SET_CNF;
    hpetReg->TIM0_COMP = (hpetFemto / (hpetReg->GCAP_ID >> 32));
    hpetReg->GEN_CONF |= HPET_ENABLE_CNF;

    return;
}

void
hpet_enable_interrupts_tim1(void) {
    // LAB 5: Your code here

    hpetReg->GEN_CONF |= HPET_ENABLE_CNF;
    hpetReg->GEN_CONF |= HPET_LEG_RT_CNF;
    hpetReg->TIM1_CONF |= HPET_TN_TYPE_CNF;
    hpetReg->TIM1_CONF |= HPET_TN_INT_ENB_CNF;

    hpetReg->GEN_CONF &= ~HPET_ENABLE_CNF;
    hpetReg->MAIN_CNT = 0;
    hpetReg->TIM1_CONF |= HPET_TN_VAL_SET_CNF;
    hpetReg->TIM1_COMP = 3 * (hpetFemto / (hpetReg->GCAP_ID >> 32)) / 2;
    hpetReg->GEN_CONF |= HPET_ENABLE_CNF;

    pic_irq_unmask(IRQ_CLOCK);
}

void
hpet_handle_interrupts_tim0(void) {

    pic_send_eoi(IRQ_TIMER);
    sched_yield();
}

void
hpet_handle_interrupts_tim1(void) {

    pic_send_eoi(IRQ_CLOCK);
    sched_yield();
}

/* Calculate CPU frequency in Hz with the help with HPET timer.
 * HINT Use hpet_get_main_cnt function and do not forget about
 * about pause instruction. */
uint64_t
hpet_cpu_frequency(void) {
    static uint64_t cpu_freq;

    uint64_t hpet_cnt_init = hpet_get_main_cnt();
    uint64_t tsc_init = read_tsc();
    
    for(int i = 0; i < 10000; i++)
        asm volatile("pause");

    uint64_t tsc_offset = read_tsc() - tsc_init;
    uint64_t hpet_cnt_offset = hpet_get_main_cnt() - hpet_cnt_init;

    cpu_freq = tsc_offset * hpetFreq / (hpet_cnt_offset);
    // LAB 5: Your code here
    
    return cpu_freq;
}

uint32_t
pmtimer_get_timeval(void) {
    FADT *fadt = get_fadt();
    return inl(fadt->PMTimerBlock);
}

/* Calculate CPU frequency in Hz with the help with ACPI PowerManagement timer.
 * HINT Use pmtimer_get_timeval function and do not forget that ACPI PM timer
 *      can be 24-bit or 32-bit. */
uint64_t
pmtimer_cpu_frequency(void) {
    static uint64_t cpu_freq;

    // LAB 5: Your code here

    //! 32 bit error?

    uint64_t pm_init_val = pmtimer_get_timeval();
    uint64_t tsc_init = read_tsc();
    
    for(int i = 0; i < 10000; i++)
        asm volatile("pause");

    uint64_t tsc_offset = read_tsc() - tsc_init;
    uint64_t pm_cur_val = pmtimer_get_timeval();
    uint64_t pm_offset = 0;

    if(pm_cur_val >= pm_init_val){
        // no overflow
        pm_offset = pm_cur_val - pm_init_val;
    }
    else if(pm_init_val - pm_cur_val <= 0x00FFFFFF){
        // overflow 24-bit case
        pm_offset = 0x00FFFFFF - pm_init_val + pm_cur_val;
    }
    else{
        // overflow 32-bit case
        pm_offset = UINT32_MAX - pm_init_val + pm_cur_val;
    }

    cpu_freq = tsc_offset * PM_FREQ / (pm_offset);

    return cpu_freq;
}
