/**
 * example_unpack.cpp
 **/

#include <iostream>
#include "packer.hpp"

int main(int argc, char **argv)
{   
    packer_t packer;
    if (!packer_read(&packer, "data/sample.exe")) {
        std::cerr << "error: unable to read target exe" << std::endl;
        return 1;
    }

    packer_encrypt(&packer, "yellow submarine");
    if (!packer_write(&packer, "sample.enc.exe")) {
        std::cerr << "error: unable to write stub file" << std::endl;
        return 1;
    }

    packer_free(&packer);
    return 0;
}