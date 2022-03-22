/**
 * example_unpack.cpp
 **/

#include <iostream>
#include "loader.hpp"

int main(int argc, char **argv)
{   
    loader_t loader;
    if (!loader_read_stub(&loader, "stub")) {
        std::cerr << "error: unable to read target stub" << std::endl;
        return 1;
    }

    loader_decrypt(&loader);
    if (!loader_write_file(&loader, "sample.exe")) {
        std::cerr << "error: unable to write file" << std::endl;
        return 1;
    }

    loader_free(&loader);
    return 0;
}