from yaml import safe_load


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
