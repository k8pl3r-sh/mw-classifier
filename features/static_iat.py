#!/usr/bin/python3


from utils.logger import Log
import lief  # https://lief.re/doc/latest/tutorials/01_play_with_formats.html

DEFAULT_FILE = "snake_deluxe.exe"


class StaticIat:
    def __init__(self, config: dict):
        self.log = Log("StaticIAT", config)

    def __repr__(self):
        return "StaticIat"

    def extract(self, filename: str) -> dict[str, list[str]]:
        """
        Extract the import address table from the PE file indicated by the 'filename' parameter, and then return the set
        Parameters
        ----------
        filename

        Returns
        -------

        """
        # TODO : check PE ici et faire les différents cas
        binary = lief.parse(filename)
        extracted = {}
        if binary is not None and binary.has_imports:
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

        self.log.debug(f"Extracted {len(extracted)} IAT from {filename}")
        return extracted
