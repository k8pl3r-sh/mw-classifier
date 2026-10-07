#!/usr/bin/python3

"""
Build per-binary graphs (node features + edge list) from the function call
graph, for the GNN. Pure numpy — no torch here.

Node features (per function):
  [log1p(#instructions), log1p(in_degree), log1p(out_degree)] + opcode-category
  histogram (fractions). Address-invariant and format-agnostic enough to compare
  across samples.
"""

import os
import math
import numpy as np

from utils.logger import Log
from utils.tools import is_supported_binary, filename_from_path
from features.call_graph import disassemble_call_graph
from evaluation.ground_truth import family_of

# Coarse x86 opcode categories (keeps the node feature small and robust).
_OPCODE_CATEGORIES = {
    "mov": "transfer", "lea": "transfer", "xchg": "transfer", "movzx": "transfer", "movsx": "transfer",
    "push": "stack", "pop": "stack",
    "add": "arith", "sub": "arith", "inc": "arith", "dec": "arith", "mul": "arith", "imul": "arith",
    "div": "arith", "idiv": "arith", "neg": "arith", "adc": "arith", "sbb": "arith",
    "and": "logic", "or": "logic", "xor": "logic", "not": "logic", "shl": "logic", "shr": "logic",
    "sar": "logic", "rol": "logic", "ror": "logic",
    "cmp": "compare", "test": "compare",
    "jmp": "branch", "je": "branch", "jne": "branch", "jz": "branch", "jnz": "branch", "jg": "branch",
    "jge": "branch", "jl": "branch", "jle": "branch", "ja": "branch", "jae": "branch", "jb": "branch",
    "jbe": "branch", "jo": "branch", "jno": "branch", "js": "branch", "jns": "branch", "loop": "branch",
    "call": "call", "ret": "call", "retn": "call",
}
_CATEGORIES = ["transfer", "stack", "arith", "logic", "compare", "branch", "call", "other"]
NODE_FEATURE_DIM = 3 + len(_CATEGORIES)


def build_graph(filename: str):
    """Return (x, edge_index) for a binary, or None if no graph can be built.

    x : np.ndarray [n_nodes, NODE_FEATURE_DIM] float32
    edge_index : np.ndarray [2, n_edges] int64 (directed, both directions added)
    """
    graph = disassemble_call_graph(filename)
    if not graph:
        return None
    func_mnemonics = graph["func_mnemonics"]
    nodes = sorted(func_mnemonics.keys())
    if not nodes:
        return None

    idx = {start: i for i, start in enumerate(nodes)}
    in_deg = {s: 0 for s in nodes}
    out_deg = {s: 0 for s in nodes}
    edge_list = []
    for src, dst in graph["edges"]:
        if src in idx and dst in idx:
            out_deg[src] += 1
            in_deg[dst] += 1
            edge_list.append((idx[src], idx[dst]))
            edge_list.append((idx[dst], idx[src]))  # add reverse for message passing

    x = np.zeros((len(nodes), NODE_FEATURE_DIM), dtype=np.float32)
    for start in nodes:
        i = idx[start]
        seq = func_mnemonics[start]
        n = len(seq)
        x[i, 0] = math.log1p(n)
        x[i, 1] = math.log1p(in_deg[start])
        x[i, 2] = math.log1p(out_deg[start])
        if n > 0:
            counts = {c: 0 for c in _CATEGORIES}
            for mnem in seq:
                counts[_OPCODE_CATEGORIES.get(mnem, "other")] += 1
            for j, cat in enumerate(_CATEGORIES):
                x[i, 3 + j] = counts[cat] / n

    if edge_list:
        edge_index = np.array(edge_list, dtype=np.int64).T
    else:
        edge_index = np.zeros((2, 0), dtype=np.int64)
    return x, edge_index


def build_dataset(samples_dir: str, log=None) -> list:
    """Walk a directory and build a graph per supported binary.

    Returns a list of dicts: {name, family, x, edge_index}.
    """
    log = log or Log("GraphBuilder")
    dataset = []
    for root, _, files in os.walk(samples_dir):
        for fname in files:
            path = os.path.join(root, fname)
            if not is_supported_binary(path):
                continue
            built = build_graph(path)
            if built is None:
                continue
            x, edge_index = built
            name = filename_from_path(path)
            dataset.append({
                "name": name,
                "family": family_of(name),
                "x": x,
                "edge_index": edge_index,
            })
    log.info(f"Built {len(dataset)} graphs from {samples_dir}")
    return dataset
