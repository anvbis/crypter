/**
 * unpack.h
 **/

#ifndef CRYPTER_UNPACK_H
#define CRYPTER_UNPACK_H

#include <string>

/* ... */
typedef struct {
    char *bytes;
    size_t size;
} pe_data_t;

/* ... */
int pe_data_read(pe_data_t *pe_data, std::string filename);

/* ... */
int pe_data_write(pe_data_t *pe_data, std::string filename);

/* ... */
void pe_data_encrypt(pe_data_t *pe_data, std::string key);

/* ... */
void pe_data_decrypt(pe_data_t *pe_data, std::string key);

#endif /* CRYPTER_UNPACK_H */
