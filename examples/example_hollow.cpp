/**
 * example_inject.cpp
 **/

#include <iostream>
#include "hollow.h"

int main(int argc, char **argv)
{
    /* read pe data into memory */
    pe_data_t pe_data;
    pe_data_read(&pe_data, "data/sample.exe");

    /* inject pe via process hollowing */
    pe_data_hollow(&pe_data, "C:\\Windows\\explorer.exe");

    pe_data_free(&pe_data);
    return 0;
}