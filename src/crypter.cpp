/**
 * main.cpp
 **/

#include <iostream>
#include "packer.hpp"

int main(int argc, char **argv)
{
    if (argc < 2) {
        std::cout << "usage: crypter.exe <target>" << std::endl;
        return 1;
    }

    std::string target(argv[1]);

    packer_t packer;
    if (!packer_read_file(&packer, target)) {
        std::cerr << "error: unable to read target executable" << std::endl;
        return 1;
    }

    packer_encrypt(&packer);
    if (!packer_write_stub(&packer, "stub")) {
        std::cerr << "error: unable to write stub file" << std::endl;
        return 1;
    }

    packer_free(&packer);
    return 0;
}
