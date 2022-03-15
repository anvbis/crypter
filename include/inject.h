/**
 * inject.h
 **/

#ifndef CRYPTER_INJECT_H
#define CRYPTER_INJECT_H

#include <windows.h>
#include "unpack.h"

/* ... */
int pe_data_inject(pe_data_t *pe_data, unsigned long pid);

#endif /* CRYPTER_INJECT_H */