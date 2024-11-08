from utils.tools import load_yml
from sys import exit

"""
Way to use it in the project :

from utils.config import Config
class SomeClass:
    def __init__(self):
        self.config = Config().get()

"""
class Config:
    _instance = None

    def __new__(cls, config=None):
        if cls._instance is None:
            cls._instance = super(Config, cls).__new__(cls)
            try:
                cls._instance.config = load_yml("config.yml") # config.yml must be in the root folder of the project
            except FileNotFoundError as e:
                print(f"Error: {e}. Ensure 'config.yml' is in the root folder of the project.")
                exit(1)

        return cls._instance

    def get(self):
        return self.config


if __name__ == "__main__":
    # Initialize once
    config = {"key": "value"}
    Config(config)  # Sets config for the singleton