/**
 * unpack.cpp
 **/

#include <fstream>
#include <cstdlib>
#include "unpack.h"

int pe_data_read(pe_data_t *pe_data, std::string filename)
{
    /* open the file */
    std::ifstream ifs;
    ifs.open(filename, std::ios::in | std::ios::binary);
    if (ifs.fail()) {
        return 0;
    }

    /* find the size of the file */
    ifs.seekg(0, std::ios::end);
    pe_data->size = ifs.tellg();
    ifs.seekg(0, std::ios::beg);

    /* read the file into memory */
    pe_data->bytes = (char*)malloc(sizeof(char) * (pe_data->size));
    ifs.read(pe_data->bytes, pe_data->size);

    ifs.close();
    return 1;
}

int pe_data_write(pe_data_t *pe_data, std::string filename)
{
    /* open the file */
    std::ofstream ofs;
    ofs.open(filename, std::ios::out | std::ios::binary);
    if (ofs.fail()) {
        return 0;
    }

    /* write the data to file */
    ofs.write(pe_data->bytes, pe_data->size);

    ofs.close();
    return 1;
}

void pe_data_encrypt(pe_data_t *pe_data, std::string key)
{
    /* simple repeating key xor for now */
    for (size_t i = 0; i < pe_data->size; ++i) {
        pe_data->bytes[i] = pe_data->bytes[i] ^ key[i % key.length()];
    }
}

void pe_data_decrypt(pe_data_t *pe_data, std::string key)
{
    /* simple repeating key xor for now */
    for (size_t i = 0; i < pe_data->size; ++i) {
        pe_data->bytes[i] = pe_data->bytes[i] ^ key[i % key.length()];
    }
}

void pe_data_free(pe_data_t *pe_data)
{
    /* free bytes allocated when reading pe file into memory */
    free(pe_data->bytes);

    /* zero-out fields for potential re-use */
    pe_data->bytes = NULL;
    pe_data->size = 0;
}