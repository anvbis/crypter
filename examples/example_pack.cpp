/**
 * example_pack.cpp
 **/

#include <iostream>
#include "loader.hpp"

int main(int argc, char **argv)
{   
    loader_t loader;
    if (!loader_read_file(&loader, "data/sample.exe")) {
        std::cerr << "error: unable to read target exe" << std::endl;
        return 1;
    }

    loader_encrypt(&loader);
    if (!loader_write_stub(&loader, "stub")) {
        std::cerr << "error: unable to write stub file" << std::endl;
        return 1;
    }

    loader_free(&loader);
    return 0;
}