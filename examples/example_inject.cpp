/**
 * example_inject.cpp
 **/

#include <iostream>
#include "inject.h"

int main(int argc, char **argv)
{
    /* read pe data into memory */
    pe_data_t pe_data;
    pe_data_read(&pe_data, "data/sample.exe");

    /* execute pe in current process */
    unsigned long pid = GetCurrentProcessId();
    pe_data_inject(&pe_data, pid);

    pe_data_free(&pe_data);
    return 0;
}