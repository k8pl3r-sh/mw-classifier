#!/usr/bin/python3

import pefile
from utils.logger import Log


class RichHeader:
    """Rich header comp.id values: fingerprints of the Microsoft toolchain
    (compiler/linker versions) used to build a PE. Shared comp.ids are a strong
    build-environment signal for family attribution."""

    def __init__(self):
        self.log = Log("RichHeader")

    def __repr__(self):
        return "RichHeader"

    def extract(self, filename: str) -> dict:
        tokens = set()
        try:
            pe = pefile.PE(filename, fast_load=True)
            rich = pe.parse_rich_header()
            pe.close()
            if rich:
                # 'values' is a flat list: [comp_id, count, comp_id, count, ...]
                values = rich.get('values', []) or []
                for i in range(0, len(values) - 1, 2):
                    tokens.add(f"compid:{values[i]}")
        except Exception as e:
            self.log.debug(f"rich header not available for {filename}: {e}")
        return {'rich_header': tokens} if tokens else {}
