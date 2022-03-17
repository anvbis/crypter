/**
 * example_injector.c
 */

#include "packer.h"
#include "injector.h"

int main(int argc, char **argv)
{
    packer_t packer;
    packer_init(&packer, "data/sample.exe");

    injector_t injector;
    injector_init(&injector, packer.bytes, packer.length);
    injector_exec(&injector, "C:\\Windows\\explorer.exe");
    
    packer_free(&packer);
    return 0;
}