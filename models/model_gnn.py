import networkx as nx
from neo4j import Session
from utils.logger import Log
from utils.config import Config

"""
Ne fonctionne pas actuellement, tout en sim à 1"""

class CFGSimilarityModel:
    def __init__(self, session: Session, neo4j, redis=None):
        self.config = Config().get()
        self.log = Log("CFGSimilarityModel")
        self.neo4j = neo4j
        self.session = session
        self.redis = redis
        self.threshold = self.config["model"]["threshold"]

    def compute_graph_similarity(self, g1: nx.Graph, g2: nx.Graph) -> float:
        """
        Compute a normalized similarity between two graphs based on graph edit distance.
        Similarity = 1 / (1 + GED), where GED is the graph edit distance.
        """
        try:
            # ensure simple Graph
            if isinstance(g1, (nx.MultiGraph, nx.MultiDiGraph)):
                g1 = nx.Graph(g1)
            if isinstance(g2, (nx.MultiGraph, nx.MultiDiGraph)):
                g2 = nx.Graph(g2)

            ged = nx.graph_edit_distance(g1, g2)
            if ged is None:
                self.log.warning("Graph edit distance returned None, defaulting to inf")
                ged = float('inf')
        except Exception as e:
            self.log.error(f"Error computing graph edit distance: {e}")
            return 0.0
        # Normalize to [0,1]
        sim = 1.0 / (1.0 + ged)
        return sim

    def create_relationships(self, cfgs: dict[str, nx.Graph], similarity_matrix: list[list[float]] = None) -> list[list[float]]:
        """
        Compare each pair of CFGs, create relationships in Neo4j
        and update the similarity matrix.
        """
        names = list(cfgs.keys())
        n = len(names)
        if similarity_matrix is None:
            similarity_matrix = [[0.0] * n for _ in range(n)]

        for i in range(n):
            for j in range(i+1, n):
                name_i, name_j = names[i], names[j]
                g1, g2 = cfgs.get(name_i), cfgs.get(name_j)
                if not isinstance(g1, nx.Graph) or not isinstance(g2, nx.Graph):
                    self.log.warning(f"Skipping pair ({name_i}, {name_j}) - invalid graph")
                    continue

                sim = self.compute_graph_similarity(g1, g2)
                similarity_matrix[i][j] = similarity_matrix[j][i] = sim

                if sim >= self.threshold:
                    try:
                        self.session.execute_write(
                            self.neo4j.create_relationship,
                            name_i, name_j, sim
                        )
                        self.log.info(f"Created relationship {name_i} - {name_j} (sim={sim:.3f})")
                    except Exception as e:
                        self.log.error(f"Error creating relationship: {e}")
        return similarity_matrix

    def extract_cfgs_from_attributes(self, malware_attributes: dict) -> dict[str, nx.Graph]:
        """
        Filter and return only valid NetworkX graphs under key 'ControlFlowGraph'.
        """
        cfgs: dict[str, nx.Graph] = {}
        for name, attrs in malware_attributes.items():
            graph_obj = attrs.get('ControlFlowGraph')
            if isinstance(graph_obj, nx.Graph):
                cfgs[name] = graph_obj
            else:
                self.log.warn(f"Invalid or missing ControlFlowGraph for {name}")
        return cfgs

    def run(self, malware_attributes: dict, similarity_matrix: list[list[float]] = None) -> list[list[float]]:
        """
        Entry point: extract CFG graphs from malware_attributes and compute similarities.

        malware_attributes: dict mapping malware name to dict with a 'ControlFlowGraph' entry.
        similarity_matrix: optional preallocated similarity matrix to update.
        """
        self.log.info("Starting CFG similarity run")
        cfgs = self.extract_cfgs_from_attributes(malware_attributes)
        self.log.info(f"Extracted {len(cfgs)} valid CFGs")

        result_matrix = self.create_relationships(cfgs, similarity_matrix)
        self.log.info("CFG similarity run completed")
        return result_matrix
