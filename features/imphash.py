#!/usr/bin/python3

import pefile
from utils.logger import Log


class Imphash:
    """Import hash (imphash): a fingerprint of the PE import table. Identical
    imphashes are a strong signal that two PE files were built from the same
    source / toolchain, which often means the same malware family."""

    def __init__(self):
        self.log = Log("Imphash")

    def __repr__(self):
        return "Imphash"

    def extract(self, filename: str) -> dict:
        try:
            pe = pefile.PE(filename, fast_load=True)
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']]
            )
            imphash = pe.get_imphash()
            pe.close()
            if imphash:
                return {'imphash': {imphash}}
        except Exception as e:
            self.log.debug(f"imphash not available for {filename}: {e}")
        return {}
