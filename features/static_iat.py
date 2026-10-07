#!/usr/bin/python3

from utils.logger import Log
import lief  # https://lief.re/doc/latest/tutorials/01_play_with_formats.html


class StaticIat:
    def __init__(self):
        self.log = Log("StaticIAT")

    def __repr__(self):
        return "StaticIat"

    def extract(self, filename: str) -> dict[str, list[str]]:
        """
        Extract imported symbols from a binary. Handles PE, ELF and Mach-O.

        - PE: imports are grouped per DLL (the key is the DLL name), preserving
          provenance.
        - ELF / Mach-O: the abstract LIEF API is used (imported functions and
          linked libraries).

        Parameters
        ----------
        filename : str

        Returns
        -------
        dict[str, list[str]]
        """
        binary = lief.parse(filename)
        extracted = {}
        if binary is None:
            return extracted

        if isinstance(binary, lief.PE.Binary):
            if binary.has_imports:
                for entry in binary.imports:
                    iat = []
                    for function in entry.entries:
                        if function.is_ordinal:
                            func_name = f"Ordinal({function.ordinal})"
                        else:
                            func_name = function.name
                        if func_name:
                            iat.append(func_name)
                        else:
                            self.log.warn(f"Error decoding import name of the PE file: {function}")
                    extracted[entry.name] = iat
        else:
            # ELF / Mach-O: use the format-agnostic imported-symbols API
            funcs = [f.name for f in binary.imported_functions if f.name]
            libs = [str(lib) for lib in getattr(binary, "libraries", [])]
            if funcs:
                extracted["imported_functions"] = funcs
            if libs:
                extracted["libraries"] = libs

        self.log.debug(f"Extracted {len(extracted)} import groups from {filename}")
        return extracted
