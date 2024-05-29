from yaml import safe_load
import os

def load_yml(filepath: str) -> dict:
    with open(filepath, 'r') as file:
        data = safe_load(file)
    return data