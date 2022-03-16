/**
 * example_unpack.cpp
 **/

#include <iostream>
#include "crypter.hpp"

int main(int argc, char **argv)
{
    /* read the sample.exe file */
    crypter::pe_data_t pe_data;
    if (!crypter::init(&pe_data, "data/sample.exe")) {
        std::cerr << "error: unable to open data/sample.exe" << std::endl; 
        return 1;
    }

    /* encrypt and write out to sample.exe.enc */
    crypter::encrypt::xor(&pe_data, "yellow submarine");
    crypter::write(&pe_data, "data/sample.enc.exe");

    crypter::free(&pe_data);

    /* read the sample.exe.enc file */
    if (!crypter::init(&pe_data, "data/sample.enc.exe")) {
        std::cerr << "error: unable to open data/sample.enc.exe" << std::endl; 
        return 1;
    }

    /* decrypt and write out to sample.dec.exe */
    crypter::decrypt::xor(&pe_data, "yellow submarine");
    crypter::write(&pe_data, "data/sample.dec.exe");

    crypter::free(&pe_data);
    return 0;
}