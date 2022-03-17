/**
 * example_unpack.cpp
 **/

#include <iostream>
#include "crypter.hpp"

int main(int argc, char **argv)
{
    /* read the sample.exe file */
    pe_data_t pe_data;
    if (!pe_data_read(&pe_data, "data/sample.exe")) {
        std::cerr << "error: unable to open data/sample.exe" << std::endl; 
        return 1;
    }

    /* encrypt and write out to sample.exe.enc */
    pe_data_encrypt(&pe_data, "yellow submarine");
    pe_data_write(&pe_data, "data/sample.enc.exe");

    pe_data_free(&pe_data);

    /* read the sample.exe.enc file */
    if (!pe_data_read(&pe_data, "data/sample.enc.exe")) {
        std::cerr << "error: unable to open data/sample.enc.exe" << std::endl; 
        return 1;
    }

    /* decrypt and write out to sample.dec.exe */
    pe_data_decrypt(&pe_data, "yellow submarine");
    pe_data_write(&pe_data, "data/sample.dec.exe");

    pe_data_free(&pe_data);
    return 0;
}