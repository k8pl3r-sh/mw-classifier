#!/usr/bin/python3

import bisect
from utils.logger import Log

# IMAGE_SCN_MEM_EXECUTE
_SCN_MEM_EXECUTE = 0x20000000
# PE32+ optional header magic
_PE32_PLUS_MAGIC = 0x20b

MAX_INSTRUCTIONS = 300000  # safety cap to bound cost on large/packed binaries


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


def disassemble_call_graph(filename: str, max_instructions: int = MAX_INSTRUCTIONS, log=None):
    """
    Linear-sweep disassembly of a PE into a function call graph.

    Returns a dict (or None on failure / non-PE / missing deps):
      - ``func_mnemonics`` : {function_start_addr: [mnemonic, ...]}
      - ``edges``          : set of (src_start_addr, dst_start_addr) call edges

    Shared by the token extractor (CallGraph) and the GNN graph builder, so both
    see exactly the same graph. capstone/pefile are imported lazily.
    """
    try:
        import pefile
        import capstone
    except ImportError as e:
        if log:
            log.debug(f"call graph needs pefile+capstone ({e}); skipping")
        return None

    try:
        pe = pefile.PE(filename, fast_load=True)
    except Exception as e:
        if log:
            log.debug(f"call graph: cannot parse {filename}: {e}")
        return None

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
                    target = _imm_target(insn.op_str)
                    if target is not None:
                        call_targets.add(target)
                count += 1
                if count >= max_instructions:
                    break
            if count >= max_instructions:
                break
    except Exception as e:
        if log:
            log.debug(f"call graph: disassembly failed for {filename}: {e}")
        return None
    finally:
        try:
            pe.close()
        except Exception:
            pass

    if not instructions:
        return None

    addresses = sorted(addr for addr, _, _ in instructions)
    addr_set = set(addresses)

    # Function entry points: the program entry point plus every call target that
    # lands on a disassembled instruction.
    starts = sorted({entrypoint} | {t for t in call_targets if t in addr_set})
    if not starts:
        starts = [addresses[0]]

    def func_of(addr: int) -> int:
        i = bisect.bisect_right(starts, addr) - 1
        return starts[i] if i >= 0 else starts[0]

    func_mnemonics = {}
    for addr, mnem, _ in instructions:
        func_mnemonics.setdefault(func_of(addr), []).append(mnem)

    edges = set()
    for addr, mnem, op in instructions:
        if mnem != "call":
            continue
        target = _imm_target(op)
        if target is None or target not in addr_set:
            continue
        edges.add((func_of(addr), func_of(target)))

    return {"func_mnemonics": func_mnemonics, "edges": edges}


class CallGraph:
    """
    Static function call graph of a PE, turned into address-invariant tokens.

    Each "function" (delimited by call targets) is hashed from its mnemonic
    sequence (operands stripped, so the hash is independent of absolute
    addresses). Emitted tokens:

      - ``func:<hash>``        one per function (shared-code signal)
      - ``edge:<src>-><dst>``  one per intra-binary call edge (call-graph shape)

    Two samples that share code produce the same hashes, so the Jaccard / MinHash
    models detect them. capstone/pefile are imported lazily.
    """

    def __init__(self):
        self.log = Log("CallGraph")

    def __repr__(self):
        return "CallGraph"

    @staticmethod
    def _hash_seq(mnemonics: list) -> int:
        import mmh3
        return mmh3.hash(" ".join(mnemonics)) & 0xFFFFFFFF

    def extract(self, filename: str) -> dict:
        graph = disassemble_call_graph(filename, MAX_INSTRUCTIONS, self.log)
        if not graph:
            return {}

        func_hash = {start: self._hash_seq(seq) for start, seq in graph["func_mnemonics"].items()}

        tokens = {f"func:{h}" for h in func_hash.values()}
        for src_start, dst_start in graph["edges"]:
            src = func_hash.get(src_start)
            dst = func_hash.get(dst_start)
            if src is not None and dst is not None:
                tokens.add(f"edge:{src}->{dst}")

        self.log.debug(f"Extracted call graph with {len(func_hash)} functions from {filename}")
        return {"call_graph": tokens} if tokens else {}
