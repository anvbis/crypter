/**
 * crypter.hpp
 */

#ifndef CRYPTER_HPP
#define CRYPTER_HPP

#include <string>

/* stores portable executable data */
typedef struct {
    char *bytes;
    size_t size;
} pe_data_t;

/* reads pe data into memory */
int pe_data_read(pe_data_t *pe_data, std::string filename);

/* writes pe data out into file */
int pe_data_write(pe_data_t *pe_data, std::string filename);

/* encrypts pe data using repeating key xor */
void pe_data_encrypt(pe_data_t *pe_data, std::string key);

/* decrypts pe data using repeating key xor */
void pe_data_decrypt(pe_data_t *pe_data, std::string key);

/* ... */
int pe_data_inject(pe_data_t *pe_data, char *target);

/* frees memory allocated when reading pe data */
void pe_data_free(pe_data_t *pe_data);

#endif /* CRYPTER_HPP */