#!/usr/bin/python3

import bisect
from utils.logger import Log

# IMAGE_SCN_MEM_EXECUTE
_SCN_MEM_EXECUTE = 0x20000000
# PE32+ optional header magic
_PE32_PLUS_MAGIC = 0x20b


class CallGraph:
    """
    Static function call graph of a PE, turned into address-invariant tokens.

    A linear sweep (capstone) disassembles the executable sections. Call targets
    are used as function boundaries; each "function" is hashed from its mnemonic
    sequence (operands stripped, so the hash is independent of absolute
    addresses). The emitted tokens are:

      - ``func:<hash>``        one per function (shared-code signal)
      - ``edge:<src>-><dst>``  one per intra-binary call edge (call-graph shape)

    Two samples that share code produce the same hashes, so the Jaccard / MinHash
    models detect them. capstone/pefile are imported lazily: if they are missing,
    the extractor returns nothing instead of breaking the pipeline.
    """

    MAX_INSTRUCTIONS = 300000  # safety cap to bound cost on large/packed binaries

    def __init__(self):
        self.log = Log("CallGraph")

    def __repr__(self):
        return "CallGraph"

    @staticmethod
    def _imm_target(op_str: str):
        """Absolute target of a direct call (capstone resolves relative calls).
        Indirect/register calls (e.g. 'call eax') return None."""
        op = op_str.strip()
        if op.startswith("0x"):
            try:
                return int(op, 16)
            except ValueError:
                return None
        return None

    @staticmethod
    def _hash_seq(mnemonics: list) -> int:
        import mmh3
        return mmh3.hash(" ".join(mnemonics)) & 0xFFFFFFFF

    def extract(self, filename: str) -> dict:
        try:
            import pefile
            import capstone
        except ImportError as e:
            self.log.debug(f"call graph needs pefile+capstone ({e}); skipping")
            return {}

        try:
            pe = pefile.PE(filename, fast_load=True)
        except Exception as e:
            self.log.debug(f"call graph: cannot parse {filename}: {e}")
            return {}

        try:
            mode = capstone.CS_MODE_64 if pe.OPTIONAL_HEADER.Magic == _PE32_PLUS_MAGIC else capstone.CS_MODE_32
            md = capstone.Cs(capstone.CS_ARCH_X86, mode)
            image_base = pe.OPTIONAL_HEADER.ImageBase
            entrypoint = image_base + pe.OPTIONAL_HEADER.AddressOfEntryPoint

            instructions = []  # (address, mnemonic, op_str)
            call_targets = set()
            count = 0
            for section in pe.sections:
                if not (section.Characteristics & _SCN_MEM_EXECUTE):
                    continue
                base = image_base + section.VirtualAddress
                for insn in md.disasm(section.get_data(), base):
                    instructions.append((insn.address, insn.mnemonic, insn.op_str))
                    if insn.mnemonic == "call":
                        target = self._imm_target(insn.op_str)
                        if target is not None:
                            call_targets.add(target)
                    count += 1
                    if count >= self.MAX_INSTRUCTIONS:
                        break
                if count >= self.MAX_INSTRUCTIONS:
                    break
        except Exception as e:
            self.log.debug(f"call graph: disassembly failed for {filename}: {e}")
            try:
                pe.close()
            except Exception:
                pass
            return {}

        try:
            pe.close()
        except Exception:
            pass

        if not instructions:
            return {}

        addresses = sorted(addr for addr, _, _ in instructions)
        addr_set = set(addresses)

        # Function entry points: the program entry point plus every call target
        # that lands on a disassembled instruction.
        starts = sorted({entrypoint} | {t for t in call_targets if t in addr_set})
        if not starts:
            starts = [addresses[0]]

        def func_of(addr: int) -> int:
            i = bisect.bisect_right(starts, addr) - 1
            return starts[i] if i >= 0 else starts[0]

        # Per-function mnemonic sequences -> address-invariant content hashes.
        func_mnemonics = {}
        for addr, mnem, _ in instructions:
            func_mnemonics.setdefault(func_of(addr), []).append(mnem)
        func_hash = {f: self._hash_seq(seq) for f, seq in func_mnemonics.items()}

        tokens = set()
        for h in func_hash.values():
            tokens.add(f"func:{h}")

        for addr, mnem, op in instructions:
            if mnem != "call":
                continue
            target = self._imm_target(op)
            if target is None or target not in addr_set:
                continue
            src = func_hash.get(func_of(addr))
            dst = func_hash.get(func_of(target))
            if src is not None and dst is not None:
                tokens.add(f"edge:{src}->{dst}")

        self.log.debug(f"Extracted call graph with {len(func_hash)} functions from {filename}")
        return {"call_graph": tokens} if tokens else {}
