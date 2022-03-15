/**
 * crypter.cpp
 **/

#include "unpack.h"
#include "inject.h"

int main(int argc, char **argv)
{
    pe_data_t pe_data;
    pe_data_read(&pe_data, "data/sample.exe");

    pe_data_encrypt(&pe_data, "yellow submarine");
    pe_data_write(&pe_data, "data/sample.exe.enc");

    pe_data_free(&pe_data);
    pe_data_read(&pe_data, "data/sample.enc.exe");

    pe_data_decrypt(&pe_data, "yellow submarine");
    pe_data_write(&pe_data, "data/sample.dec.exe");

    pe_data_free(&pe_data);
    return 0;
}
