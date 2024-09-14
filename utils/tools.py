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
    with open(filepath, 'r') as file:
        data = safe_load(file)
    return data


def pe_check(fullpath: str) -> bool:
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
