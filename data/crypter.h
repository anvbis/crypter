/**
 * crypter.h
 */

#ifndef CRYPTER_H
#define CRYPTER_H

typedef struct {
    char *bytes;
    size_t size;
} pe_data_t;

int pe_data_read(pe_data_t *pe_data, char *filename);
int pe_data_write(pe_data_t *pe_data, char *filename);
void pe_data_encrypt(pe_data_t *pe_data, char *key);
void pe_data_decrypt(pe_data_t *pe_data, char *key);
int pe_data_inject(pe_data_t *pe_data, char *target);
void pe_data_free(pe_data_t *pe_data);

#endif /* CRYPTER_H */