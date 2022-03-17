/**
 * example_packer.c
 */

#include "packer.h"

int main(int argc, char **argv)
{
    packer_t packer;
    if (!packer_init(&packer, "data/sample.exe")) {
        return 1;
    }

    packer_encrypt_xor(&packer, "yellow submarine");
    if (!packer_write_stub(&packer, "data/sample.enc.exe")) {
        return 1;
    }

    packer_free(&packer);
    if (!packer_init(&packer, "data/sample.enc.exe")) {
        return 1;
    }

    packer_decrypt_xor(&packer, "yellow submarine");
    if (!packer_write_stub(&packer, "data/sample.dec.exe")) {
        return 1;
    }

    packer_free(&packer);
    return 0;
}