/**
 * crypter.hpp
 */

#ifndef CRYPTER_HPP
#define CRYPTER_HPP

#include <string>

namespace crypter {
    /* stores portable executable data */
    typedef struct {
        char *bytes;
        size_t size;
    } pe_data_t;

    /* reads pe data into memory */
    int init(pe_data_t *pe, std::string filename);

    /* write pe data out into file */
    int write(pe_data_t *pe, std::string filename);

    namespace encrypt {
        /* encrypts pe data using repeating key xor */
        void xor(pe_data_t *pe, std::string key);
    }

    namespace decrypt {
        /* decrypts pe data using repeating key xor */
        void xor(pe_data_t *pe, std::string key);
    }

    /* executes pe via process hollowing */
    int inject(pe_data_t *pe, std::string target);

    /* frees memory allocated when reading pe data */
    void free(pe_data_t *pe);
}

#endif /* CRYPTER_HPP */