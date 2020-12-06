#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#define PAE_MAXPHYADDR 52 // MAXPHYADDR for PAE
#define LEGACY_MAXPHYADDR 32 // MAXPHYADDR from Legacy translations

// Delete this block if no debug is supposed to be happening
#ifndef VA2PA_DEBUG_ON
    #define VA2PA_DEBUG_ON
#endif

#ifdef VA2PA_DEBUG_ON
    #include <time.h>
#endif

/* -------------------------------------------------------------------------- */
/*                                 DEFINITIONS                                */
/* -------------------------------------------------------------------------- */

// Result codes (basically error codes)
typedef enum {
    ST_SUCCESS_32, // Success code 0
    ST_INCORRECT_LEVEL_32, // Wrong level specified (neither 3 nor 2)
    ST_RAM_READ_ERROR_32, // PREAD_FUNC returned 0 thus an error occured
    ST_PDE_NOT_PRESENT_32, // Present bit of PDE is not set
    ST_PTE_NOT_PRESENT_32, // Present bit of PTE is not set
    ST_PDE_SUPERVISOR_MODE_32, // PDE is in supervisor mode and cannot be accessed
    ST_PTE_SUPERVISOR_MODE_32, // PTE is in supervisor mode and cannot be accessed
    ST_PDE_PSE_32, // PS bit is set therefore directory is inaccessible in 4-KiB mode (only with PSE enabled)
    ST_PDPTE_NOT_PRESENT_32, // Present bit of PDPTE is not set
    ST_PDPTE_RESERVED_32, // PDPTE reserved bits are set
    ST_PDE_RESERVED_32, // PDE reserved bits are set
    ST_PTE_RESERVED_32, // PTE reserved bits are set
    ST_PML4E_NOT_PRESENT_32, // Present bit of PDE is not set
    ST_PML4E_SUPERVISOR_MODE_32, // PDE is in supervisor mode and cannot be accessed
    ST_PML4E_MBZ_32, // PML4E MustBeZero bits are set (not zero)
    ST_PTE_PAE_PAT_32, // PTE PAT Bit in PAE mode must be unset
    ST_PDE_PSE_PAT_32 // PAT bit should be zero in PSE mode
} TranslationState32;

/* -------------- PAE and Legacy Translation Entities Bit Maps -------------- */

// Struct represents PDE bit indices
typedef struct {
    const uint8_t present, rw, uaccess, pwt, pcd, accessed, dirty, pse, global, pat, addrstart, addrend;
    const uint64_t reserved;
} PDEBitTable32;

// PDE Legacy Bit Table
static const PDEBitTable32 PDEBits = {
    .present = 0, /* present bit - 0 bit (last bit) */
    .rw = 1, /* read/write bit - 1 bit */
    .uaccess = 2, /* user/supervisor access bit - 2 bit */
    .pwt = 3, /* Page write-through bit - 3 bit */
    .pcd = 4, /* Page cache disabled - 4 bit */
    .accessed = 5, /* accessed bit - 5 */
    .pse = 7, /* page size extension - 7 bit */
    .addrstart = 12, /* page table address start */
    .addrend = LEGACY_MAXPHYADDR - 1 /* page table address end */
};

static const PDEBitTable32 PDE4MbBits = {
    .present = 0, .rw = 1, .uaccess = 2, .pwt = 3, .pcd = 4, .accessed = 5, .dirty = 6, .pse = 7, .global = 8, .pat = 12,
    .reserved = 0x3FE000
};

static const PDEBitTable32 PDE2MbBits = {
    .present = 0, .rw = 1, .uaccess = 2, .pwt = 3, .pcd = 4, .accessed = 5, .dirty = 6, .pse = 7, .global = 8, .pat = 12,
    .addrstart = 21, .addrend = PAE_MAXPHYADDR - 1,
    .reserved = 0xFFF00000001FE000
};

// PDE PAE Bit Table
static const PDEBitTable32 PDEBitsPAE = {
    .present = 0, .rw = 1, .uaccess = 2, .pwt = 3, .pcd = 4, .accessed = 5, .pse = 7, 
    .addrstart = 12, .addrend = PAE_MAXPHYADDR - 1,
    .reserved = 0xFFF0000000000000
};

// Struct represents PTE bit indices
typedef struct {
    const uint8_t present, rw, uaccess, pwt, pcd, accessed, dirty, pat, global, addrstart, addrend;
    const uint64_t reserved;
} PTEBitTable32;

// PDE Legacy Bit Table
static const PTEBitTable32 PTEBits = {
    .present = 0, /* present bit - 0 bit (last bit) */
    .rw = 1, /* read/write bit - 1 bit */
    .uaccess = 2, /* user/supervisor access bit - 2 bit */
    .pwt = 3, /* Page write-through bit - 3 bit */
    .pcd = 4, /* Page cache disabled - 4 bit */
    .accessed = 5, /* accessed bit - 5 */
    .dirty = 6, /* dirty flag - 6 bit */
    .pat = 7, /* page size extension - 7 bit */
    .global = 8, /* global flag - 8 bit */
    .addrstart = 12, /* physical address start */
    .addrend = LEGACY_MAXPHYADDR - 1 /* physical address end */
};

// PDE PAE Bit Table
static const PTEBitTable32 PTEBitsPAE = {
    .present = 0, .rw = 1, .uaccess = 2, .pwt = 3, .pcd = 4, .accessed = 5, .dirty = 6, .pat = 7, .global = 8, 
    .addrstart = 12, .addrend = PAE_MAXPHYADDR - 1,
    .reserved = 0xFFF0000000000000
};

// Struct represents PDPTE bit indices
typedef struct {
    const uint8_t present, pwt, pcd, pse, addrstart, addrend;
    const uint64_t reserved, reserved64PSE;
} PDPTEBitTablePAE;

// PAE PDPTE Bit Table
static const PDPTEBitTablePAE PDPTEBits = {
    .present = 0, /* present bit - 0 bit (last bit) */
    .pwt = 3, /* Page write-through bit - 3 bit */
    .pcd = 4, /* Page cache disabled - 4 bit */
    .pse = 7, /* Page size extension - 7 bit */
    .addrstart = 12, /* physical directory address start */
    .addrend = PAE_MAXPHYADDR - 1, /* page directory address end */
    .reserved = 0xFFF00000000001E6, /* ranges of reserved bits that should be all 0 */
    .reserved64PSE = 0x3FFFE000 /* reserved bit for pse in long mode*/
}; 

// Struct represents CR3 register bit indices
typedef struct {
    const uint8_t pwt, pcd, addrstart, addrend;
    const uint64_t mbz;
} CR3BitTable;

// CR3 Legacy Bit Table
static const CR3BitTable CR3Bits32 = {
    .pwt = 3, /* Page write-through bit - 3 bit */
    .pcd = 4, /* Page cache disabled - 4 bit */
    .addrstart = 12, /* page directory address start */
    .addrend = 31 /* page directory address end */
};

// CR3 PAE Bit Table
static const CR3BitTable CR3BitsPAE = {
    .addrstart = 5, .addrend = 31 
};

/* ----------------- Long Mode (x64) Mode Entities Bit Maps ----------------- */

// Struct represents PML4E bit indicies
typedef struct {
    const uint8_t present, rw, uaccess, pwt, pcd, accessed, addrstart, addrend;
    const uint64_t mbz;
} PML4EBitTable;

// PML4E Bit Table
static const PML4EBitTable PML4EBits = {
    .present = 0, .rw = 1, .uaccess = 2, .pwt = 3, .pcd = 4, .accessed = 5,
    .addrstart = 12, .addrend = 51, 
    .mbz = 0x300 // MustBeZero bits
};

// CR3 Long Mode Bit Table
static const CR3BitTable CR3Bits64 = {
    .addrstart = 12, .addrend = PAE_MAXPHYADDR - 1,
    .mbz = 0xFFF0000000000000
};

// Basically, PDPTE, PDE and PTE bit structures are the same fro PAE and Long mode paging

/* -------------------------------------------------------------------------- */
/*                                AUX FUNCTIONS                               */
/* -------------------------------------------------------------------------- */

#ifdef VA2PA_DEBUG_ON
uint64_t randbits(int bytes) {
    uint64_t result = 0;
    uint64_t currand = 0;

    for (int i = 0; i < bytes; i++) {
        currand = (rand() & 0xff);
        result |= currand << (i * 8);
    }

    return result;
}

// Dummy implementation of PREAD_FUNC just for debugging purposes
unsigned int dbg_read_func(void *buf, const unsigned int size, const unsigned int physical_addr) {
    uint64_t targetData = randbits(size);
    targetData |= 0x5; // Setting present bit and user access bit
    
    if (size == sizeof(uint32_t)) {
        *(uint32_t*) buf = targetData;    
    } else if (size == sizeof(uint64_t)) {
        *(uint64_t*) buf = targetData;
    }
    
    return size;
}

// Dummy implementation of PREAD_FUNC_64 just for debugging purposes
unsigned int dbg_read_func_64(void *buf, const unsigned int size, const uint64_t physical_addr) {
    uint64_t targetData = randbits(size);
    targetData |= 0x5; // Setting present bit and user access bit
    *(uint64_t*) buf = targetData;
    return size;
}
#endif

// Function prints a 4 byte uint in binary
void printbits(uint64_t value, uint8_t length) {
   for (uint8_t bit = 0; bit < length * 8; bit++) {
      printf(((bit + 1) % 4 == 0 ? "%llu " : "%llu"), value & 1);
      value >>= 1;
   }
   printf("\n");
}

// Function prints a particular error message for each error code in TranslationState32 enum
void printerr(TranslationState32 resultState) {
    static const char* errmsgs[] = {
        "Success\n", // ST_SUCCESS_32
        "Wrong level specified, should be 2 or 3\n", // ST_INCORRECT_LEVEL_32
        "Error while reading physical memory", // ST_RAM_READ_ERROR_32
        "PDE is inaccessible - present bit is not set", // ST_PDE_NOT_PRESENT_32
        "PTE is inaccessible - present bit is not set", // ST_PTE_NOT_PRESENT_32
        "PDE is inaccessible - supervisor mode is set", // ST_PDE_SUPERVISOR_MODE_32
        "PTE is inaccessible - supervisor mode is set", // ST_PTE_SUPERVISOR_MODE_32
        "PDE is inaccessible is 4-KiB mode - PSE is enabled", // ST_PDE_PSE_32
        "PDPTE present bit is not set", // ST_PDPTE_NOT_PRESENT_32
        "PDPTE reserved bits are set", // ST_PDPTE_RESERVED_32
        "PDE reserved bits are set", // ST_PDE_RESERVED_32
        "PTE reserved bits are set", // ST_PTE_RESERVED_32
        "PTE PAT bit is set when it should be reserved", // ST_PTE_PAE_PAT_32
        "Present bit of PML4E is not set", // ST_PML4E_NOT_PRESENT_32
        "PML4E is in supervisor mode and cannot be accessed", // ST_PML4E_SUPERVISOR_MODE_3
        "PML4E MustBeZero bits are set (not zero)", // ST_PML4E_MBZ_32
        "PTE PAT Bit in PAE mode must be unset", // ST_PTE_PAE_PAT_32
        "PAT bit should be zero in PSE mode" // ST_PDE_PSE_PAT_32
    };
    
    printf("%s", errmsgs[resultState]);
}

/* -------------------------------------------------------------------------- */
/*                           MAIN API IMPLEMENTATION                          */
/* -------------------------------------------------------------------------- */

/**
 * @name PREAD_FUNC
 * @param buf
 *  Buffer, that will hold the data, stored at a given physical address in RAM
 * @param size
 *  Amount of data in bytes that will be read from a given physical address in RAM
 * @param physical_addr
 *  4-byte physical memory address
 * @returns unsigned int 
 *  Returns an amount of bytes successfully read from RAM
 * @description:
 *  Function reads certaing amount of data from RAM at a certain address and stores 
 *  that data into a buffer, passed as an arguement. Function returns an amount of bytes, 
 *  successfully read from memory, 0 or less means an out of bounds exception or another error 
 */
typedef unsigned int (*PREAD_FUNC)(void *buf, const unsigned int size, const unsigned int physical_addr);

/**
 * @name: PREAD_FUNC_64
 * @description:
 *  Same as PREAD_FUNC, just read memory address from 64-bit address
 */
typedef unsigned int (*PREAD_FUNC_64)(void *buf, const unsigned int size, const uint64_t physical_addr);

/**
 * @name va2pa
 * @param virt_addr
 *  4-byte virtual address to be tranlated into physical address
 * @param level
 *  Level of indirection w/ values 2 or 3 which stand for legacy translation and PAE translation respectively
 * @param root_addr
 *  Page directory root address (similar to CR3 register value in x86 architecture)
 * @param read_func
 *  Function pointer that accepts a PREAD_FUNC function that reads a certain amount of physical memory
 * @param phys_addr
 *  Integer pointer that will hold a resulting physical address after a given virtual address is 
 *  successfully translated (output buffer)
 * @returns int
 *  Function returns 0 if translation was carried out succesfully or returns value other than zero if errors occured
 * @description: 
 *  Function performs a translation of a given virtual address into physical address and stores it in an output buffer
 */
int va2pa(
    const unsigned int virt_addr, 
    const unsigned int level, 
    const unsigned int root_addr, 
    const PREAD_FUNC read_func, 
    //unsigned int *phys_addr
    uint64_t *phys_addr // since PAE translations produce 52-bit physical address
) {
    if (level > 3 || level < 2) { // Return error if a wrong level is given
        #ifdef VA2PA_DEBUG_ON
            printerr(ST_INCORRECT_LEVEL_32);
        #endif

        return ST_INCORRECT_LEVEL_32;
    }
    
    #ifdef VA2PA_DEBUG_ON
        uint32_t void_ptr_token_32 = 0;
        uint64_t void_ptr_token_64 = 0;
    #endif

    if (level == 2) {
        // BEGINNING OF LEVEL 2 LEGACY TRANSLATION

        // Init buffer to read PDE from memory
        uint32_t* pde = malloc(sizeof(uint32_t));

        // calculating pde address using CR3 (root addr) and virt_addr
        uint32_t pde_addr = (root_addr >> CR3Bits32.addrstart) + (virt_addr >> 22) * sizeof(uint32_t);

        // reading pde data from RAM
        if ((*read_func)(pde, sizeof(uint32_t), pde_addr) < sizeof(uint32_t)) {
            #ifdef VA2PA_DEBUG_ON
                printerr(ST_RAM_READ_ERROR_32);
                printf(" at addr: 0x%08x bytes to read: %lu\n", pde_addr, sizeof(uint32_t));
            #endif

            return ST_RAM_READ_ERROR_32;
        }

        // uint32_t *pde = *((uint32_t*) pde); // Casting read PDE data to 4 byte int
        TranslationState32 PDEIntegrityCheck = ST_SUCCESS_32;
        
        if (!(*pde & (1 << PDEBits.present))) {  // if pde present bit is not set
            PDEIntegrityCheck = ST_PDE_NOT_PRESENT_32;
        } else if (!(*pde & (1 << PDEBits.uaccess))) { // if pde is in supervisor mode
            PDEIntegrityCheck = ST_PDE_SUPERVISOR_MODE_32;
        } else if (*pde & (1 << PDEBits.pse)) { // if pse bit is set
            // Big page PSE mode is on
            if (*pde && PDE4MbBits.reserved) {
                PDEIntegrityCheck = ST_PDE_RESERVED_32;
            } else if (!(*pde & (1 << PDE4MbBits.pat))) {
                PDEIntegrityCheck = ST_PDE_PSE_PAT_32;
            }
        }
        
        // if pde is somehow corrupt
        if (PDEIntegrityCheck != ST_SUCCESS_32) {
            // print error and return error code
            #ifdef VA2PA_DEBUG_ON
                printerr(PDEIntegrityCheck);
                printf(" pde: ");
                printbits((uint64_t) *pde, sizeof(uint32_t));
            #endif
            
            return PDEIntegrityCheck;
        }

        if (*pde & (1 << PDEBits.pse)) { // IF PAGE SIZE EXTENSION IS ON
            *phys_addr = (*pde & 0xFFC00000) + (virt_addr & 0x3FFFFE);
            free(pde);
        } else { // IF PAGE SIZE EXTENSION IS OFF
            // Getting PTE address from PDE data
            uint32_t pte_addr = (*pde >> 12) + ((virt_addr >> 12) & 0x3FF) * sizeof(uint32_t);
            free(pde);

            // Init buffer to read PTE from memory
            uint32_t* pte = malloc(sizeof(uint32_t));

            // reading pte data from RAM
            if ((*read_func)(pte, sizeof(uint32_t), pte_addr) < sizeof(uint32_t)) {
                #ifdef VA2PA_DEBUG_ON
                    printerr(ST_RAM_READ_ERROR_32);
                    printf(" at addr: 0x%08x bytes to read: %lu\n", pte_addr, sizeof(uint32_t));
                #endif

                return ST_RAM_READ_ERROR_32;
            }
            
            TranslationState32 PTEIntegrityCheck = ST_SUCCESS_32;

            if (!(*pte & (1 << PTEBits.present))) { // if pte present bit is not set
                PTEIntegrityCheck = ST_PTE_NOT_PRESENT_32;
            } else if (!(*pte & (1 << PTEBits.uaccess))) { // if pte is in supervisor mode
                PTEIntegrityCheck = ST_PTE_SUPERVISOR_MODE_32;
            }

            // if pte is somehow corrupt
            if (PTEIntegrityCheck != ST_SUCCESS_32) {
                // print error and return error code
                #ifdef VA2PA_DEBUG_ON
                    printerr(PTEIntegrityCheck);
                    printf(" pte: ");
                    printbits((uint64_t) *pte, sizeof(uint32_t));
                #endif

                return PTEIntegrityCheck;
            }
            
            // Display a warning if a dirty bit is set
            if (!(*pte & (1 << PTEBits.dirty))) {
                printf("WARNING: PTE dirty bit is set\n");
            }
            
            // Unsetting 12 least significant bits
            // And adding offset from virtual address
            *phys_addr = (uint64_t)((*pte & 0xFFFFF000) + (virt_addr & 0xFFF));
            free(pte);
        }
        
        // END OF LEVEL 2 LEGACY TRANSLATION
    } else if (level == 3) {
        // BEGINNING OF LEVEL 3 PAE TRANSLATION

        // Init buffer to read PDPTE data from memory
        uint64_t* pdpte = malloc(sizeof(uint64_t));

        // calculating pde address using CR3 (root addr) and virt_addr
        uint64_t pdpte_addr = (root_addr >> CR3BitsPAE.addrstart) + (virt_addr >> 30) * sizeof(uint64_t);

        // Reading pdpte data from memory
        if ((*read_func)(pdpte, sizeof(uint64_t), pdpte_addr) < sizeof(uint64_t)) {
            #ifdef VA2PA_DEBUG_ON
                printerr(ST_RAM_READ_ERROR_32);
                printf(" at addr: 0x%08llx bytes to read: %lu\n", pdpte_addr, sizeof(uint64_t));
            #endif

            return ST_RAM_READ_ERROR_32;
        }
        
        TranslationState32 PDPTEIntegrityCheck = ST_SUCCESS_32;

        if (!(*pdpte & (1 << PDPTEBits.present))) { // Check if present
            PDPTEIntegrityCheck = ST_PDPTE_NOT_PRESENT_32; 
        } 
        
        if (*pdpte & PDPTEBits.reserved) { // Check if any of the reserved bits are set
            PDPTEIntegrityCheck = ST_PDPTE_RESERVED_32;
        }

        // if pdpte is somehow corrupt
        if (PDPTEIntegrityCheck != ST_SUCCESS_32) {
            // display an error message and return error code
            #ifdef VA2PA_DEBUG_ON
                printerr(PDPTEIntegrityCheck);
                printf(" pdpte: ");
                printbits(*pdpte, sizeof(uint64_t));
            #endif
            
            return PDPTEIntegrityCheck;
        }

        // Calculating PDE address from PDPTE data
        uint64_t pde_addr_pae = ((*pdpte >> 12) & 0xFFFFFFFFFF) + ((virt_addr >> 21) & 0x1FF) * sizeof(uint64_t);
        free(pdpte);

        // Init buffer to read PDE data from memory
        uint64_t* pde_pae = malloc(sizeof(uint64_t));

        // Reading PDE data from memory
        if ((*read_func)(pde_pae, sizeof(uint64_t), pde_addr_pae) < sizeof(uint64_t)) {
            #ifdef VA2PA_DEBUG_ON
                printerr(ST_RAM_READ_ERROR_32);
                printf(" at addr: 0x%08llx bytes to read: %lu\n", pde_addr_pae, sizeof(uint64_t));
            #endif

            return ST_RAM_READ_ERROR_32;
        }

        TranslationState32 PDEIntegrityCheckPAE = ST_SUCCESS_32;

        if (!(*pde_pae & (1 << PDEBitsPAE.present))) { // Check if present
            PDEIntegrityCheckPAE = ST_PDE_NOT_PRESENT_32; 
        } else if (!(*pde_pae & (1 << PDEBitsPAE.uaccess))) { // Check if accessible by user
            PDEIntegrityCheckPAE = ST_PDE_SUPERVISOR_MODE_32;
        } 
        
        if (*pde_pae & (1 << PDEBitsPAE.pse)) { // Check if page size is not extended
            if (*pde_pae & PDE2MbBits.reserved) {
                PDEIntegrityCheckPAE = ST_PDE_RESERVED_32;
            } else if (!(*pde_pae & (1 << PDE2MbBits.pat))) {
                PDEIntegrityCheckPAE = ST_PDE_PSE_PAT_32;
            }
        } else if (*pde_pae & PDEBitsPAE.reserved) { // Check if any of the reserved bits are set
            PDEIntegrityCheckPAE = ST_PDE_RESERVED_32;
        }

        // If PDE is somehow corrupt
        if (PDEIntegrityCheckPAE != ST_SUCCESS_32) {
            // Display an error message and return error code
            #ifdef VA2PA_DEBUG_ON
                printerr(PDEIntegrityCheckPAE);
                printf(" pde: ");
                printbits(*pde_pae, sizeof(uint64_t));
            #endif

            return PDEIntegrityCheckPAE;
        }

        if (*pde_pae & (1 << PDEBitsPAE.pse)) { // IF PAGE SIZE EXTENSION IS ENABLED (2Mb Page Directory Entry)
            *phys_addr = (*pde_pae & 0xFFFFFFFE00000) + (virt_addr & 0x1FFFFF);
            free(pde_pae);
        } else { // IF PAGE SIZE EXTENSION IS DISABLED
             // Calculating PTE address from PDE data
            uint64_t pte_addr_pae = ((*pde_pae >> 12) & 0xFFFFFFFFFF) + ((virt_addr >> 12) & 0x1FF) * sizeof(uint64_t);
            free(pde_pae);

            // Init buffer to read PTE from memory
            uint64_t* pte_pae = malloc(sizeof(uint64_t));

            // Reading PTE data from memory
            if ((*read_func)(pte_pae, sizeof(uint64_t), pte_addr_pae) < sizeof(uint64_t)) {
                #ifdef VA2PA_DEBUG_ON
                    printerr(ST_RAM_READ_ERROR_32);
                    printf(" at addr: 0x%08llx bytes to read: %lu\n", pte_addr_pae, sizeof(uint64_t));
                #endif
                
                return ST_RAM_READ_ERROR_32;
            }

            TranslationState32 PTEIntegrityCheckPAE = ST_SUCCESS_32;

            if (!(*pte_pae & (1 << PTEBitsPAE.present))) { // Check if present
                PTEIntegrityCheckPAE = ST_PTE_NOT_PRESENT_32; 
            } else if (!(*pte_pae & (1 << PTEBitsPAE.uaccess))) { // Check if accessible by user
                PTEIntegrityCheckPAE = ST_PDE_SUPERVISOR_MODE_32;
            } else if (!(*pte_pae & (1 << PTEBitsPAE.pat))) { // Check if PAT bit is resereved
                PTEIntegrityCheckPAE = ST_PTE_PAE_PAT_32;
            } 
            
            if (*pte_pae & PTEBitsPAE.reserved) { // Check if any of the reserved bits are set
                PTEIntegrityCheckPAE = ST_PTE_RESERVED_32;
            }

            // If PTE is somehow corrupt
            if (PTEIntegrityCheckPAE != ST_SUCCESS_32) {
                // Dispaly an error message and return error code
                #ifdef VA2PA_DEBUG_ON
                    printerr(PTEIntegrityCheckPAE);
                    printf(" pte: ");
                    printbits(*pte_pae, sizeof(uint64_t));
                #endif
                
                return PTEIntegrityCheckPAE;
            }

            // Display a warning if a dirty bit is set
            #ifdef VA2PA_DEBUG_ON
                if (!(*pte_pae & (1 << PTEBitsPAE.dirty))) {
                    printf("WARNING: PTE dirty bit is set\n");
                }
            #endif
            
            // Unsetting 12 least significant bits
            // And adding offset from virtual address
            *phys_addr = (*pte_pae & 0xFFFFFFFFFFFFF000) + (virt_addr & 0xFFF);
            free(pte_pae);
        }
        // END OF LEVEL 3 PAE TRANSLATION
    }

    // return successfull result
    return ST_SUCCESS_32;
}

/**
 * @name: va2pa_64
 * @description:
 *  Same as va2pa, only for 64 but translation with 64-bit CR3, 64-bit return physical address buffer and
 *  64-bit PREAD_FUNC_64 instead of PREAD_FUNC to read from RAM 
 */
uint8_t va2pa_64(
    const uint64_t virt_addr_64, 
    const uint64_t root_addr_64, 
    const PREAD_FUNC_64 read_func_64, 
    uint64_t *phys_addr_64
) {
    #ifdef VA2PA_DEBUG_ON
        uint32_t void_ptr_token_32 = 0;
        uint64_t void_ptr_token_64 = 0;
    #endif

    // Init buffer to read PML4E data from memory
    uint64_t* pml4e = malloc(sizeof(uint64_t));

    // calculation pml4e address using CR3 and virt_addr
    uint64_t pml4e_addr = ((root_addr_64 >> CR3Bits64.addrstart) & 0xFFFFFFFFFF) + ((virt_addr_64 >> 39) & 0x1FF) * sizeof(uint64_t);

    // Reading pml4e data from memory
    if ((*read_func_64)(pml4e, sizeof(uint64_t), pml4e_addr) < sizeof(uint64_t)) {
        #ifdef VA2PA_DEBUG_ON
            printerr(ST_RAM_READ_ERROR_32);
            printf(" at addr: 0x%08llx bytes to read: %lu\n", pml4e_addr, sizeof(uint64_t));
            return ST_RAM_READ_ERROR_32;
        #endif
    }

    TranslationState32 PML4EIntegrityCheck = ST_SUCCESS_32;

    if (!(*pml4e & (1 << PML4EBits.present))) { // Check if present
        PML4EIntegrityCheck = ST_PDPTE_NOT_PRESENT_32; 
    } else if (!(*pml4e & (1 << PML4EBits.uaccess))) { // Check if accessible by user
        PML4EIntegrityCheck = ST_PDE_SUPERVISOR_MODE_32;
    } else if (*pml4e & PML4EBits.mbz) {
        PML4EIntegrityCheck = ST_PML4E_MBZ_32;
    }

    // If PDE is somehow corrupt
    if (PML4EIntegrityCheck != ST_SUCCESS_32) {
        // Display an error message and return error code
        #ifdef VA2PA_DEBUG_ON
            printerr(PML4EIntegrityCheck);
            printf(" pde: ");
            printbits(*pml4e, sizeof(uint64_t));
        #endif
        
        return PML4EIntegrityCheck;
    }

    // Init buffer to read PDPTE data from memory
    uint64_t* pdpte = malloc(sizeof(uint64_t));

    // calculating pdpte address using PML4E and virt_addr
    uint64_t pdpte_addr = ((*pml4e >> PML4EBits.addrstart) & 0xFFFFFFFFFF) + ((virt_addr_64 >> 30) & 0x1FF) * sizeof(uint64_t);
    free(pml4e);

    // Reading pdpte data from memory
    if ((*read_func_64)(pdpte, sizeof(uint64_t), pdpte_addr) < sizeof(uint64_t)) {
        #ifdef VA2PA_DEBUG_ON
            printerr(ST_RAM_READ_ERROR_32);
            printf(" at addr: 0x%08llx bytes to read: %lu\n", pdpte_addr, sizeof(uint64_t));
        #endif
        
        return ST_RAM_READ_ERROR_32;
    }

    TranslationState32 PDPTEIntegrityCheck = ST_SUCCESS_32;

    if (!(*pdpte & (1 << PDPTEBits.present))) { // Check if present
        PDPTEIntegrityCheck = ST_PDPTE_NOT_PRESENT_32; 
    } 

    if (*pdpte & (1 << PDPTEBits.pse)) { // If PSE is enabled
        if (*pdpte & PDPTEBits.reserved64PSE) { // Check if any of the reserved bits are set
            PDPTEIntegrityCheck = ST_PDPTE_RESERVED_32;
        }
    }

    // if pdpte is somehow corrupt
    if (PDPTEIntegrityCheck != ST_SUCCESS_32) {
        // display an error message and return error code
        #ifdef VA2PA_DEBUG_ON
            printerr(PDPTEIntegrityCheck);
            printf(" pdpte: ");
            printbits(*pdpte, sizeof(uint64_t));
        #endif
        
        return PDPTEIntegrityCheck;
    }

    if (*pdpte & (1 << PDPTEBits.pse)) { // IF 1Gb PDPE PSE IS ENABLE IN LONG MODE
        *phys_addr_64 = (*pdpte & 0xFFFFFC0000000) + (virt_addr_64 & 0x3FFFFFFF);
        free(pdpte);
    } else { // IF 1Gb PDPE PSE IS DISABLED
         // Calculating PDE address from PDPTE data
        uint64_t pde_addr_64 = ((*pdpte >> 12) & 0xFFFFFFFFFF) + ((virt_addr_64 >> 21) & 0x1FF) * sizeof(uint64_t);
        free(pdpte);

        // Init buffer to read PDE data from memory
        uint64_t* pde_64 = malloc(sizeof(uint64_t));

        // Reading PDE data from memory
        if ((*read_func_64)(pde_64, sizeof(uint64_t), pde_addr_64) <= 0) {
            #ifdef VA2PA_DEBUG_ON
                printerr(ST_RAM_READ_ERROR_32);
                printf(" at addr: 0x%08llx bytes to read: %lu\n", pde_addr_64, sizeof(uint64_t));
            #endif
            
            return ST_RAM_READ_ERROR_32;
        }

        TranslationState32 PDEIntegrityCheckPAE = ST_SUCCESS_32;

        if (!(*pde_64 & (1 << PDEBitsPAE.present))) { // Check if present
            PDEIntegrityCheckPAE = ST_PDPTE_NOT_PRESENT_32; 
        } else if (!(*pde_64 & (1 << PDEBitsPAE.uaccess))) { // Check if accessible by user
            PDEIntegrityCheckPAE = ST_PDE_SUPERVISOR_MODE_32;
        } 
        
        if (*pde_64 & (1 << PDEBitsPAE.pse)) { // Check if page size is not extended
            if (*pde_64 & PDE2MbBits.reserved) {
                PDEIntegrityCheckPAE = ST_PDE_RESERVED_32;
            }
        } else {
            if (*pde_64 & PDEBitsPAE.reserved) { // Check if any of the reserved bits are set
                PDEIntegrityCheckPAE = ST_PDE_RESERVED_32;
            }
        }

        // If PDE is somehow corrupt
        if (PDEIntegrityCheckPAE != ST_SUCCESS_32) {
            // Display an error message and return error code
            #ifdef VA2PA_DEBUG_ON
                printerr(PDEIntegrityCheckPAE);
                printf(" pde: ");
                printbits(*pde_64, sizeof(uint64_t));
            #endif

            return PDEIntegrityCheckPAE;
        }

        if (*pde_64 & (1 << PDEBitsPAE.pse)) { // IF PSE IS ENABLED FOR LONG MODE 2Mb PDE
            *phys_addr_64 = (*pde_64 & 0xFFFFFFFE00000) + (virt_addr_64 & 0x1FFFFE);
            free(pde_64);
        } else { // IF PSE FOR LONG MODE PDE IS DISABLED
            // Calculatin PTE address from PDE data
            uint64_t pte_addr_64 = ((*pde_64 >> 12) & 0xFFFFFFFFFF) + ((virt_addr_64 >> 12) & 0x1FF) * sizeof(uint64_t);
            free(pde_64);

            // Init buffer to read PTE from memory
            uint64_t* pte_64 = malloc(sizeof(uint64_t));

            // Reading PTE data from memory
            if ((*read_func_64)(pte_64, sizeof(uint64_t), pte_addr_64) < sizeof(uint64_t)) {
                #ifdef VA2PA_DEBUG_ON
                    printerr(ST_RAM_READ_ERROR_32);
                    printf(" at addr: 0x%08llx bytes to read: %lu\n", pte_addr_64, sizeof(uint64_t));
                #endif

                return ST_RAM_READ_ERROR_32;
            }

            TranslationState32 PTEIntegrityCheckPAE = ST_SUCCESS_32;

            if (!(*pte_64 & (1 << PTEBitsPAE.present))) { // Check if present
                PTEIntegrityCheckPAE = ST_PDPTE_NOT_PRESENT_32; 
            } else if (!(*pte_64 & (1 << PTEBitsPAE.uaccess))) { // Check if accessible by user
                PTEIntegrityCheckPAE = ST_PDE_SUPERVISOR_MODE_32;
            } else if (!(*pte_64 & (1 << PTEBitsPAE.pat))) { // Check if PAT bit is resereved
                PTEIntegrityCheckPAE = ST_PTE_PAE_PAT_32;
            }
            
            if (*pte_64 & PTEBitsPAE.reserved) { // Check if any of the reserved bits are set
                PTEIntegrityCheckPAE = ST_PTE_RESERVED_32;
            }

            // If PTE is somehow corrupt
            if (PTEIntegrityCheckPAE != ST_SUCCESS_32) {
                // Dispaly an error message and return error code
                #ifdef VA2PA_DEBUG_ON
                    printerr(PTEIntegrityCheckPAE);
                    printf(" pte: ");
                    printbits(*pte_64, sizeof(uint64_t));
                #endif

                return PTEIntegrityCheckPAE;
            }

            // Display a warning if a dirty bit is set
            #ifdef VA2PA_DEBUG_ON
                if (!(*pte_64 & (1 << PTEBitsPAE.dirty))) {
                    printf("WARNING: PTE dirty bit is set\n");
                }
            #endif

            // Unsetting 12 least significant bits
            // And adding offset from virtual address
            *phys_addr_64 = (*pte_64 & 0xFFFFFFFFFFFFF000) + (virt_addr_64 & 0xFFF);
            free(pte_64);
        }
    }

    // Return successful result code
    return ST_SUCCESS_32;
}

#ifdef VA2PA_DEBUG_ON
int main(int argc, char* argv[]) {
    srand(time(NULL));

    PREAD_FUNC read32 = &dbg_read_func;
    PREAD_FUNC_64 read64 = &dbg_read_func_64;
    
    uint64_t* paddr_32 = malloc(sizeof(uint64_t));

    int tempres = 0;

    printf("------------- LEVEL 2 -------------\n\n");
    for (int i = 0; i < 5; i++) {
        tempres = va2pa(randbits(2), 2, randbits(2), read32, paddr_32);
        if (tempres == 0) {
            printf("Physical address: 0x%llX\n", *paddr_32);
        }
        printf("\n");
    }

    printf("------------- LEVEL 3 -------------\n\n");
    for (int i = 0; i < 5; i++) {
        tempres = va2pa(randbits(2), 3, randbits(2), read32, paddr_32);
        if (tempres == 0) {
            printf("Physical address: 0x%llX\n", *paddr_32);
        }
        printf("\n");
    }

    printf("------------- LEVEL 4 -------------\n\n");
    for (int i = 0; i < 5; i++) {
        tempres = va2pa_64(randbits(2), randbits(2), read64, paddr_32);
        if (tempres == 0) {
            printf("Physical address: 0x%llX\n", *paddr_32);
        }
        printf("\n");
    }

    free(paddr_32);
    return 0;
}
#endif