#!/usr/bin/env python3
import os
from utils.logger import Log

DEFAULT_FILE = "snake_deluxe.exe"


class Strings:
    def __init__(self, config: dict):
        self.log = Log("Strings", config)

    def __repr__(self):
        return "Strings"

    def extract(self, filename: str) -> dict:
        """
        Extract strings from the binary indicated by the 'filename' parameter, and then return the set of unique strings in
        the binary.
        Parameters
        ----------
        filename

        Returns
        -------

        """
        strings = os.popen("strings '{0}'".format(filename)).read()
        strings = set(strings.split("\n"))
        self.log.debug(f"Extracted {len(strings)} strings from {filename}")
        return {'strings': strings}
