#!/usr/bin/python3

import lief
from utils.logger import Log


class PeSections:
    """Section-level features: name, binned entropy and binned size. Works for
    PE/ELF/Mach-O via LIEF. Numeric values are bucketed into tokens so they fit
    the token-set / Jaccard representation used by the models."""

    def __init__(self):
        self.log = Log("PeSections")

    def __repr__(self):
        return "PeSections"

    @staticmethod
    def _bucket_entropy(entropy: float) -> str:
        if entropy < 1.0:
            return "very_low"
        if entropy < 5.0:
            return "low"
        if entropy < 6.5:
            return "medium"
        if entropy < 7.2:
            return "high"
        return "packed"  # > 7.2 is typically compressed/encrypted

    @staticmethod
    def _bucket_size(size: int) -> str:
        # Order-of-magnitude bucket (power of two) to stay robust to small diffs.
        return f"2e{size.bit_length() - 1}" if size > 0 else "0"

    def extract(self, filename: str) -> dict:
        tokens = set()
        try:
            binary = lief.parse(filename)
            if binary is None:
                return {}
            for section in binary.sections:
                name = (section.name or "").replace("\x00", "").strip() or "<noname>"
                tokens.add(f"name:{name}")
                try:
                    tokens.add(f"entropy:{name}:{self._bucket_entropy(section.entropy)}")
                except Exception:
                    pass
                size = getattr(section, "size", 0) or 0
                tokens.add(f"size:{name}:{self._bucket_size(int(size))}")
        except Exception as e:
            self.log.debug(f"section features not available for {filename}: {e}")
        return {'pe_sections': tokens} if tokens else {}
