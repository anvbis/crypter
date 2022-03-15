/**
 * inject.cpp
 **/

#include "inject.h"

/* ... */
HANDLE pe_data_load(pe_data_t *pe_data, HANDLE hproc);

/* ... */
unsigned long get_ldr_offset(pe_data_t *pe_data);

/* ... */
unsigned long rva_to_offset(unsigned long rva, UINT_PTR addr);

int pe_data_inject(pe_data_t *pe_data, unsigned long pid)
{
    /* open target process */
    HANDLE hproc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, pid);
    if (!hproc) {
        return 0;
    }

    /* load remote library */
    HANDLE hmod = pe_data_load(pe_data, hproc);
    if (!hmod) {
        return 0;
    }

    /* wait for process to finish */
    WaitForSingleObject(hmod, -1);
    return 1;
}

HANDLE pe_data_load(pe_data_t *pe_data, HANDLE hproc)
{
    /* TODO */
    return 0;
}

unsigned long get_ldr_offset(pe_data_t *pe_data)
{
    UINT_PTR addr = (UINT_PTR)pe_data->bytes;
    UINT_PTR export_dir = addr + ((PIMAGE_DOS_HEADER)addr)->e_lfanew;

#ifdef WIN_X64
    if (((PIMAGE_NT_HEADERS)export_dir)->OptionalHeader.Magic == 0x10B) {
        return 0;
    }
#else
    if (((PIMAGE_NT_HEADERS)export_dir)->OptionalHeader.Magic == 0x20B) {
        return 0;
    }
#endif

    /* TODO */

    return 1;
}

unsigned long rva_to_offset(unsigned long rva, UINT_PTR addr)
{
    PIMAGE_NT_HEADERS nt_hdrs;
    nt_hdrs = (PIMAGE_NT_HEADERS)(addr + ((PIMAGE_DOS_HEADER)addr)->e_lfanew);

    PIMAGE_SECTION_HEADER sec_hdr;
    sec_hdr = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&nt_hdrs->OptionalHeader) +
            nt_hdrs->FileHeader.SizeOfOptionalHeader);

    if (rva < sec_hdr[0].PointerToRawData) {
        return rva;
    }

    for (WORD i = 0; i < nt_hdrs->FileHeader.NumberOfSections; ++i) {
        if (rva >= sec_hdr[i].VirtualAddress &&
                rva < sec_hdr[i].VirtualAddress + sec_hdr[i].SizeOfRawData) {
            return rva - sec_hdr[i].VirtualAddress + sec_hdr[i].PointerToRawData;
        }
    }

    return 0;
}