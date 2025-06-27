#!/usr/bin/env python3
import r2pipe
import networkx as nx
import pydot
from utils.logger import Log



class ControlFlowGraph:
    def __init__(self):
        self.log = Log("ControlFlowGraph")
        self.is_hashable = False

    def __repr__(self):
        return "ControlFlowGraph"

    def extract(self, filename: str) -> nx.Graph | None:
        """
        Extract a Control Flow Graph from a binary using r2pipe, return as NetworkX graph.
        """
        try:
            self.log.debug(f"Extracting CFG from {filename}")
            r2 = r2pipe.open(filename, flags=['-2'])
            # flags=['-2'] : https://r2wiki.readthedocs.io/en/latest/home/radare2-python-scripting/
            # Disable stderr messages



            r2.cmd("aaaa")  # Advanced analysis
            dot = r2.cmd("agfd .")
            r2.quit()

            if not dot.strip():
                self.log.warn("Empty CFG output")
                return None
            with open("out_debug.dot", "w") as f:
                f.write(dot)

            # Convert DOT string to networkx graph
            (graph,) = pydot.graph_from_dot_data(dot)
            G = nx.nx_pydot.from_pydot(graph).to_undirected()
            self.log.debug(f"Extracted CFG with {G.number_of_nodes()} nodes and {G.number_of_edges()} edges")
            return G

        except Exception as e:
            self.log.error(f"Error extracting CFG from {filename}: {e}")
            return None
