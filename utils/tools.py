from yaml import safe_load
import os
import random


def load_yml(filepath: str) -> dict:
    """
    Load a YAML file and return its contents as a dictionary.

    Args:
        filepath (str): The path to the YAML file to be loaded.

    Returns:
        dict: The contents of the YAML file as a dictionary.
    """
    try:
        with open(filepath, 'r') as file:
            data = safe_load(file)
        return data
    except FileNotFoundError:
        raise FileNotFoundError(f"The file '{filepath}' was not found. Please check the path and try again.")


def is_pe_file(fullpath: str) -> bool:
    """
    Perform a cursory sanity check to verify that 'fullpath' is a Windows PE executable.
    Windows PE executables start with the two bytes 'MZ'.

    Args:
        fullpath (str): The full path to the file to check.

    Returns:
        bool: True if the file starts with 'MZ', indicating it is a PE executable, False otherwise.
    """
    try:
        with open(fullpath, 'rb') as file:
            return file.read(2) == b'MZ'
    except FileNotFoundError as e:
        raise e


# Mach-O magics (thin binaries, both endiannesses). The fat/universal magic
# 0xcafebabe is intentionally excluded because it collides with Java .class files.
_MACHO_MAGICS = {
    b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf',
    b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe',
}


def is_supported_binary(fullpath: str) -> bool:
    """
    Check whether 'fullpath' is a binary LIEF can parse: PE (MZ), ELF (\\x7fELF)
    or Mach-O. Cursory magic-byte sniff only.

    Args:
        fullpath (str): The full path to the file to check.

    Returns:
        bool: True if the file looks like a supported executable format.
    """
    try:
        with open(fullpath, 'rb') as file:
            magic = file.read(4)
    except (FileNotFoundError, IsADirectoryError, PermissionError):
        return False
    if magic[:2] == b'MZ':          # PE / MS-DOS
        return True
    if magic == b'\x7fELF':         # ELF
        return True
    return magic in _MACHO_MAGICS   # Mach-O


def filename_from_path(path: str) -> str:
    """
    Extract the filename from a given file path.

    Args:
        path (str): The full path to the file.

    Returns:
        str: The filename extracted from the given path.
    """
    return os.path.basename(path)


def generate_hex_color() -> str:
    """
    Generate a random color in hexadecimal format.
    """
    return "#" + ''.join([random.choice('0123456789ABCDEF') for _ in range(6)])
