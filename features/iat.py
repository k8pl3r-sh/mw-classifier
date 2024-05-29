#!/usr/bin/python3
import pefile

DEFAULT_FILE = "snake_deluxe.exe"


def extract_iat(filename):
    pe = pefile.PE(filename)
    pe.parse_data_directories()
    iat = []
    extracted = {}
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            iat.append(imp.name.decode("utf-8"))
        extracted[entry.dll.decode("utf-8")] = iat
    return extracted


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Extract Import Address Table (IAT) from a PE file.')
    parser.add_argument('filename', nargs='?', default=DEFAULT_FILE, help='Path to the PE file (default: %(default)s)')

    args = parser.parse_args()

    if args.filename == DEFAULT_FILE:
        print("Using default file: snake_deluxe.exe")
        print("Please specify with the -f flag to extract the IAT from a different binary.")

    iat = extract_iat(args.filename)
    print(iat)
