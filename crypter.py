from lief import PE
from Crypto.Random import get_random_bytes

KEY_SIZE = 1024


def align(x, al):
    if x % al == 0:
        return x
    else:
        return x - (x % al) + al


def pad_data(data, al):
    return data + ([0] * (align(len(data), al) - len(data)))


def read_pe(filename):
    key = list(get_random_bytes(KEY_SIZE))
    with open(filename, 'rb') as f:
        data = f.read()

    data = [(data[i] ^ key[i % KEY_SIZE]) & 0xff for i in range(len(data))]
    return key + data


def main():
    unpacker = PE.parse('bin/main.exe')
    data = read_pe('data/shell.exe')

    file_alignment = unpacker.optional_header.file_alignment
    data = pad_data(data, file_alignment)

    section = PE.Section('.custom')
    section.size = len(data)
    section.content = data
    section.characteristics = (PE.SECTION_CHARACTERISTICS.MEM_READ 
            | PE.SECTION_CHARACTERISTICS.MEM_WRITE
            | PE.SECTION_CHARACTERISTICS.CNT_INITIALIZED_DATA)
    
    unpacker.add_section(section)
    unpacker.optional_header.sizeof_image = 0

    builder = PE.Builder(unpacker)
    builder.build()
    builder.write('stub.exe')


if __name__ == '__main__':
    main()