/**
 * crypter.hpp
 */

#ifndef CRYPTER_HPP
#define CRYPTER_HPP

#include <string>

#define KEY_SIZE 256

typedef struct packer {
    char key[KEY_SIZE];
    char *bytes;
    size_t size;
} packer_t;

int packer_read_file(packer_t *packer, const std::string &filename);
int packer_write_file(packer_t *packer, const std::string &filename);
int packer_read_stub(packer_t *packer, const std::string &filename);
int packer_write_stub(packer_t *packer, const std::string &filename);
void packer_encrypt(packer_t *packer);
void packer_decrypt(packer_t *packer);
int packer_inject(packer_t *packer, const std::string &target);
void packer_free(packer_t *packer);

#endif /* CRYPTER_HPP */