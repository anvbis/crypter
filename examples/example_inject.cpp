/**
 * example_inject.cpp
 **/

#include "loader.hpp"

int main(int argc, char **argv)
{
    loader_t loader;
    if (!loader_read_file(&loader, "data/sample.exe")) {
        return 1;
    }

    if (!loader_inject(&loader, "c:/windows/system32/svchost.exe")) {
        return 1;
    }

    loader_free(&loader);
    return 0;
}