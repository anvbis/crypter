/**
 * packer.h
 */

#ifndef CRYPTER_PACKER_H
#define CRYPTER_PACKER_H

#include <stddef.h>

typedef struct packer {
    char *bytes;
    size_t length;
} packer_t;

int packer_init(packer_t *packer, char *filename);
void packer_encrypt_xor(packer_t *packer, char *key);
void packer_decrypt_xor(packer_t *packer, char *key);
int packer_write_stub(packer_t *packer, char *filename);
void packer_free(packer_t *packer);

#endif /* CRYPTER_PACKER_H_ */