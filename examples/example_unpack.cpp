/**
 * example_unpack.cpp
 **/

#include <iostream>
#include "packer.hpp"

int main(int argc, char **argv)
{   
    packer_t packer;
    if (!packer_read_stub(&packer, "stub")) {
        std::cerr << "error: unable to read target stub" << std::endl;
        return 1;
    }

    packer_decrypt(&packer);
    if (!packer_write_file(&packer, "sample.exe")) {
        std::cerr << "error: unable to write file" << std::endl;
        return 1;
    }

    packer_free(&packer);
    return 0;
}