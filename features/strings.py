#!/usr/bin/env python3
import os
from utils.logger import Log
from utils.config import Config

class Strings:
    def __init__(self):
        self.log = Log("Strings")

    def __repr__(self):
        return "Strings"

    def extract(self, filename: str) -> dict | None:
        """
        Extract strings from the binary indicated by the 'filename' parameter, and then return the set of unique strings in
        the binary.
        Parameters
        ----------
        filename

        Returns
        -------

        """
        try:
            raw_strings = os.popen("strings '{0}'".format(filename)).read()
            strings = set(raw_strings.split("\n"))
            self.log.debug(f"Extracted {len(strings)} strings from {filename}")
            return {'strings': strings}
        except Exception as e:
            self.log.error(f"Error extracting strings from {filename} : {e}")
            return None