#!/usr/bin/env python3
import os


DEFAULT_FILE = "snake_deluxe.exe"


def get_strings(fullpath: str) -> set:
    """
    Extract strings from the binary indicated by the 'fullpath'
    parameter, and then return the set of unique strings in
    the binary.
    """
    strings = os.popen("strings '{0}'".format(fullpath)).read()
    strings = set(strings.split("\n"))
    return strings


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Extract Strings from a file.')
    parser.add_argument('filename', nargs='?', default=DEFAULT_FILE, help='Path to the file (default: %(default)s)')

    args = parser.parse_args()

    if args.filename == DEFAULT_FILE:
        print("Using default file: snake_deluxe.exe")
        print("Please specify with the -f flag to extract the strings from a different file.")

    strings = get_strings(args.filename)
    print(strings)
