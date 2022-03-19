/**
 * crypter.hpp
 */

#ifndef CRYPTER_HPP
#define CRYPTER_HPP

#include <string>

typedef struct packer {
    char *bytes;
    size_t size;
} packer_t;

int packer_read(packer_t *packer, const std::string &filename);
int packer_write(packer_t *packer, const std::string &filename);
void packer_encrypt(packer_t *packer, const std::string &key);
void packer_decrypt(packer_t *packer, const std::string &key);
int packer_inject(packer_t *packer, const std::string &target);
void packer_free(packer_t *packer);

#endif /* CRYPTER_HPP */