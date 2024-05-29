from neo4j import Transaction
import itertools
from utils.ml_functions import jaccard


def create_node_cypher(path: str) -> str:
    return f"CREATE (m:Malware {{path: '{path}'}});\n"


def create_relationship_cypher(path1, path2, weight) -> str:
    return f"MATCH (a:Malware {{path: '{path1}'}}), (b:Malware {{path: '{path2}'}}) CREATE (a)-[:SIMILAR {{weight: {weight}}}]->(b);\n"


def create_node(tx: Transaction, path: str):
    query = (
        "CREATE (m:Malware {path: $path}) "
        "RETURN id(m)"
    )
    tx.run(query, path=path)


# noinspection PyTypeChecker
def create_relationship(tx: Transaction, path1: str, path2: str, weight: float):
    query = (
        "MATCH (a:Malware {path: $path1}), (b:Malware {path: $path2}) "
        "CREATE (a)-[:SIMILAR {weight: $weight}]->(b)"
    )
    tx.run(query, path1=path1, path2=path2, weight=weight)


def save_graph_as_cypher(malware_paths: list[str], malware_attributes, threshold: float, filename: str = "graph.cypher"):
    """
    Save the graph as a Cypher script for later import into Neo4j.
    """
    with open(filename, "w") as cypher_file:
        for path in malware_paths:
            cypher_file.write(create_node_cypher(path))

        for malware1, malware2 in itertools.combinations(malware_paths, 2):
            jaccard_index = jaccard(malware_attributes[malware1], malware_attributes[malware2])
            if jaccard_index > threshold:
                cypher_file.write(create_relationship_cypher(malware1, malware2, jaccard_index))

    print(f"Cypher script saved as {filename}")
