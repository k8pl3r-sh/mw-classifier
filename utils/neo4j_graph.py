from neo4j.exceptions import CypherSyntaxError
from neo4j import Transaction
import itertools
from utils.logger import Log

from subprocess import run, CalledProcessError, PIPE
from time import sleep
from requests import get, ConnectionError
from utils.tools import generate_hex_color

from sklearn.metrics import jaccard_score


class Neo4jGraph:
    def __init__(self, config: dict):
        self.log = Log("Neo4jGraph", config)
        self.config = config
        self.labels_colors = {}  # Store labels colors if already set

    def start_neo4j_container(self):
        """
        Start a Neo4j Docker container. If an existing container named 'neo4j' is found, it will be removed first.

        This method ensures that a new Neo4j container is running and waits until it is accessible at http://localhost:7474.

        Examples:
            # >>> neo = Neo4jUtility(config)
            # >>> neo.start_neo4j_container()
            Removing existing Neo4j container...
            Starting a new Neo4j container...
            Waiting for Neo4j to start...
            Neo4j is up and running.
        """
        def run_command(command: str) -> str:
            process = run(command, shell=True, check=True, stdout=PIPE, stderr=PIPE)
            return process.stdout.decode('utf-8')

        self.log.info("Removing existing Neo4j container...")
        try:
            run_command('docker rm --force neo4j')
        except CalledProcessError:
            self.log.info("No existing container to remove or failed to remove it.")

        self.log.info("Starting a new Neo4j container...")
        run_command('docker run --rm --name neo4j -p 7474:7474 -p 7687:7687 -d -e NEO4J_AUTH=neo4j/password neo4j:latest')

        # Waiting for Neo4J will be made in another function to delay the pending time

    def check_up(self):
        # En réalité ne fait pas gagner tant de temps car peu de samples
        self.log.info("Waiting for Neo4j to start...")
        while True:
            try:
                response = get("http://localhost:7474")
                if response.status_code == 200:
                    break
            except ConnectionError:
                pass
            sleep(1)

        self.log.info("Neo4j is up and running.")

    def get_color_by_label(self, label: str):
        if label in self.labels_colors:
            return self.labels_colors[label]
        else:
            c = generate_hex_color()
            self.labels_colors[label] = c
            return c

    @staticmethod
    def create_node_cypher(label: str, path: str) -> str:
        # TODO change label
        return f"CREATE (m:{label} {{path: '{path}'}});\n"

    @staticmethod
    def create_relationship_cypher(path1: str, path2: str, weight: str) -> str:
        # TODO change label
        return f"MATCH (a:Malware {{path: '{path1}'}}), (b:Malware {{path: '{path2}'}}) CREATE (a)-[:SIMILAR {{weight: {weight}}}]->(b);\n"

    def create_node(self, tx: Transaction, label: str, properties: dict):
        # properties : dict with keys and values of properties names and values

        query = (
            "CREATE (n:" + label + " {" + ", ".join([f"{key}: '{value}'" for key, value in properties.items()]) + "})"
            "RETURN n"  # do not use id() as it is deprecied
        )
        try:
            tx.run(query)
        except CypherSyntaxError:
            self.log.error(f"Error creating node with query: {query}")

    @staticmethod
    def create_relationship(tx: Transaction, path1: str, path2: str, weight: float):
        query = (
            "MATCH (a {path: $path1}), (b {path: $path2}) "
            "CREATE (a)-[:SIMILAR {weight: $weight}]->(b)"
        )
        tx.run(query, path1=path1, path2=path2, weight=weight)

    def save_graph_as_cypher(self, malware_paths: list[str], malware_attributes, threshold: float, filename: str = "graph.cypher"):
        # TODO : redundant code here
        """
        Save the graph as a Cypher script for later import into Neo4j.
        """
        # TODO: généraliser la fonction
        with open(filename, "w") as cypher_file:
            for path in malware_paths:
                cypher_file.write(Neo4jGraph.create_node_cypher("Malware", path))

            for malware1, malware2 in itertools.combinations(malware_paths, 2):
                """
                Cette fonction ne devrait pas réaliser les relations mais les transmettre ?
                TODO : généralisation à faire ici car StaticIat/Strings en hard
                ATTENTION : changement dans le code pour le FeatureHasher 
                -> Code fonctionnel avant de commit et de push
                
                1) Boucle for pour les différentes features
                2) Moyenne entre les indices de Jaccard pour chaque feature ?
                """
                # jaccard replaced by jaccard_score
                jaccard_index = jaccard_score(malware_attributes[malware1]['Strings'], malware_attributes[malware2]['Strings'])
                if jaccard_index > threshold:
                    cypher_file.write(Neo4jGraph.create_relationship_cypher(malware1, malware2, jaccard_index))

        self.log.info(f"Cypher script saved as {filename}")
