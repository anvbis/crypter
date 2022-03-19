/**
 * main.cpp
 **/

#include <iostream>
#include "packer.hpp"

int main(int argc, char **argv)
{
    if (argc < 3) {
        std::cout << "usage:\n" << argv[0] << " " << "<target> <key>" << std::endl;
        return 1;
    }

    std::string target(argv[1]);
    std::string key(argv[2]);

    packer_t packer;
    if (!packer_read(&packer, target)) {
        std::cerr << "error: unable to read target exe" << std::endl;
        return 1;
    }

    packer_encrypt(&packer, key);
    if (!packer_write(&packer, "stub")) {
        std::cerr << "error: unable to write stub file" << std::endl;
        return 1;
    }

    packer_free(&packer);
    return 0;
}
