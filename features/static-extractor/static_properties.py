#!/usr/bin/python3


from utils.logger import Log
import lief  # https://lief.re/doc/latest/tutorials/01_play_with_formats.html


class StaticProperties:
    def __init__(self):
        self.log = Log("StaticProperties")

    def __repr__(self):
        return "StaticProperties"

    def extract(self, filename: str) -> set:
        """
        Extract the static properties from the PE file indicated by the 'filename' parameter, and then return the set
        Parameters
        ----------
        filename

        Returns
        -------
        extracted[entry.name] = iat : return a dict of keys: values

        """
        # TODO : check PE ici et faire les différents cas
        binary = lief.parse(filename)
        extracted = {}
        if binary is not None :
            self.log.debug(f"Binary Headers\n{binary.header}")
            self.log.debug(f"Binary Optional Headers\n{binary.optional_header}")
            ...
            #extracted[entry.name] = iat

        #self.log.debug(f"Extracted {len(extracted)} properties from {filename}")
        return set(extracted) # TODO : solve the issue for static IAT then apply the solution found here

if __name__ == "__main__":
    from utils.tools import load_yml
    sp = StaticProperties(load_yml("../../config.yml"))
    file = "ircbot.exe"
    sp.extract(file)