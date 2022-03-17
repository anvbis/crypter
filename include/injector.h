/**
 * injector.h
 */

#ifndef CRYPTER_INJECTOR_H
#define CRYPTER_INJECTOR_H

#include <stddef.h>
#include <windows.h>

typedef struct pe_module {
    char *bytes;
    size_t length;
    IMAGE_DOS_HEADER *dos_hdr;
    IMAGE_NT_HEADERS *nt_hdrs;
#ifdef _WIN64
    unsigned long long pref_base;
#else
    unsigned long pref_base;
#endif
} pe_module_t;

typedef struct process {
    PROCESS_INFORMATION info;
    CONTEXT thread_context;
} process_t;

typedef struct injector {
    char *bytes;
    size_t length;
    pe_module_t *pem;
    process_t *proc;
} injector_t;

int injector_init(injector_t *injector, char *bytes, size_t length);
int injector_exec(injector_t *target);

#endif /* CRYPTER_INJECTOR_H_ */