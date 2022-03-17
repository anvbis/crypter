/**
 * packer.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "packer.h"

int packer_init(packer_t *packer, char *filename)
{
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        return 0;
    }

    fseek(fp, 0, SEEK_END);
    packer->length = ftell(fp);
    rewind(fp);

    packer->bytes = (char*)malloc(sizeof(char) * packer->length);
    fread(packer->bytes, packer->length, 1, fp);

    fclose(fp);
    return 1;
}

void packer_encrypt_xor(packer_t *packer, char *key)
{
    for (int i = 0; i < packer->length; ++i) {
        packer->bytes[i] ^= key[i % strlen(key)];
    }
}

void packer_decrypt_xor(packer_t *packer, char *key)
{
    for (int i = 0; i < packer->length; ++i) {
        packer->bytes[i] ^= key[i % strlen(key)];
    }
}

int packer_write_stub(packer_t *packer, char *filename)
{
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        return 0;
    }

    fwrite(packer->bytes, sizeof(char), packer->length, fp);

    fclose(fp);
    return 1;
}

void packer_free(packer_t *packer)
{
    free(packer->bytes);
    packer->bytes = NULL;
    packer->length = 0;
}
