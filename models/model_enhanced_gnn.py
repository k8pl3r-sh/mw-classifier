import networkx as nx
from neo4j import Session
from utils.logger import Log
from utils.config import Config
import Levenshtein  # Assuming this is installed: pip install python-Levenshtein

"""donne tj sim = 1"""

class EnhancedCFGSimilarityModel:
    def __init__(self, session: Session, neo4j, redis=None):
        self.config = Config().get()
        self.log = Log("EnhancedCFGSimilarityModel")
        self.neo4j = neo4j
        self.session = session
        self.redis = redis
        self.threshold = self.config["model"]["threshold"]

        # Define weights for different attribute types. These weights should be tuned
        # based on the specific characteristics of your malware CFGs and analytical priorities.
        self.NODE_ATTR_WEIGHTS = {
            'instruction_sequence': 5.0,  # High weight for core behavioral logic
            'api_calls': 3.0,  # Moderate weight for functional indicators
            'node_kind': 1.0,  # Lower weight for structural type
            'is_entrypoint': 0.5  # Even lower for boolean flags
        }
        self.EDGE_ATTR_WEIGHTS = {
            'edge_type': 1.0  # Weight for control flow type
        }

    def _node_substitution_cost(self, node1_attrs: dict, node2_attrs: dict) -> float:
        """
        Calculates the cost of substituting node1 with node2 based on their attributes.
        Returns a positive numeric value.
        """
        cost = 0.0

        # 1. Compare 'instruction_sequence' (assuming it's a list of strings or a single string)
        # Use Levenshtein distance for sequence comparison.
        instr_seq1 = node1_attrs.get('instruction_sequence', )
        instr_seq2 = node2_attrs.get('instruction_sequence', )

        # Convert list of instructions to a single string for Levenshtein comparison
        s1 = " ".join(instr_seq1) if isinstance(instr_seq1, list) else str(instr_seq1)
        s2 = " ".join(instr_seq2) if isinstance(instr_seq2, list) else str(instr_seq2)

        if s1 and s2:
            # Normalize Levenshtein distance by the length of the longer string
            # This ensures cost is between 0 and 1 for this component
            max_len = max(len(s1), len(s2))
            if max_len > 0:
                instr_cost = Levenshtein.distance(s1, s2) / max_len
            else:  # Both are empty strings, consider them identical
                instr_cost = 0.0
            cost += instr_cost * self.NODE_ATTR_WEIGHTS.get('instruction_sequence', 0.0)
        elif s1 or s2:  # One is empty, the other is not - implies a significant difference
            cost += 1.0 * self.NODE_ATTR_WEIGHTS.get('instruction_sequence', 0.0)

        # 2. Compare 'api_calls' (assuming it's a set of strings)
        # Use Jaccard dissimilarity for set comparison.
        api_calls1 = node1_attrs.get('api_calls', set())
        api_calls2 = node2_attrs.get('api_calls', set())

        if api_calls1 or api_calls2:
            intersection_size = len(api_calls1.intersection(api_calls2))
            union_size = len(api_calls1.union(api_calls2))
            if union_size > 0:
                jaccard_sim = intersection_size / union_size
                api_cost = 1.0 - jaccard_sim  # Jaccard dissimilarity
            else:  # Both sets are empty, consider them identical
                api_cost = 0.0
            cost += api_cost * self.NODE_ATTR_WEIGHTS.get('api_calls', 0.0)

        # 3. Compare 'node_kind' (categorical attribute)
        node_kind1 = node1_attrs.get('node_kind')
        node_kind2 = node2_attrs.get('node_kind')
        if node_kind1 != node_kind2:
            cost += 1.0 * self.NODE_ATTR_WEIGHTS.get('node_kind', 0.0)

        # 4. Compare 'is_entrypoint' (boolean flag)
        is_entrypoint1 = node1_attrs.get('is_entrypoint', False)
        is_entrypoint2 = node2_attrs.get('is_entrypoint', False)
        if is_entrypoint1 != is_entrypoint2:
            cost += 1.0 * self.NODE_ATTR_WEIGHTS.get('is_entrypoint', 0.0)

        return cost

    def _edge_substitution_cost(self, edge1_attrs: dict, edge2_attrs: dict) -> float:
        """
        Calculates the cost of substituting edge1 with edge2 based on their attributes.
        Returns a positive numeric value.
        """
        cost = 0.0
        # Compare 'edge_type' (categorical attribute)
        edge_type1 = edge1_attrs.get('edge_type')
        edge_type2 = edge2_attrs.get('edge_type')

        if edge_type1 != edge_type2:
            cost += 1.0 * self.EDGE_ATTR_WEIGHTS.get('edge_type', 0.0)
        return cost

    def compute_graph_similarity(self, g1: nx.Graph, g2: nx.Graph) -> float:
        """
        Compute a normalized similarity between two graphs based on graph edit distance,
        considering node and edge attributes.
        Similarity = 1 / (1 + GED), where GED is the graph edit distance.
        """
        try:
            # ensure simple Graph
            if isinstance(g1, (nx.MultiGraph, nx.MultiDiGraph)):
                g1 = nx.Graph(g1)
            if isinstance(g2, (nx.MultiGraph, nx.MultiDiGraph)):
                g2 = nx.Graph(g2)

            # Pass custom cost functions to graph_edit_distance
            ged = nx.graph_edit_distance(
                g1, g2,
                node_subst_cost=self._node_substitution_cost,
                edge_subst_cost=self._edge_substitution_cost,
                # node_del_cost and node_ins_cost default to 1, as do edge_del_cost and edge_ins_cost
                # These defaults are generally appropriate unless specific domain knowledge suggests otherwise.
            )
            if ged is None:
                self.log.warn("Graph edit distance returned None, defaulting to inf")
                ged = float('inf')
        except Exception as e:
            self.log.error(f"Error computing graph edit distance: {e}")
            return 0.0
        # Normalize to
        sim = 1.0 / (1.0 + ged)
        return sim

    def create_relationships(self, cfgs: dict[str, nx.Graph], similarity_matrix: list[list[float]] = None) -> list[
        list[float]]:
        """
        Compare each pair of CFGs, create relationships in Neo4j
        and update the similarity matrix.
        """
        names = list(cfgs.keys())
        n = len(names)
        if similarity_matrix is None:
            similarity_matrix = [[0.0] * n for _ in range(n)]

        for i in range(n):
            for j in range(i + 1, n):
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
                self.log.warn(f"Invalid or missing ControlFlowGraph for {name}")  # Corrected from.warn to.warning
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