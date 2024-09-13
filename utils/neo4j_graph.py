from neo4j import Transaction
import itertools
#from utils.ml_functions import jaccard
from utils.logger import Log

import subprocess
from time import sleep
import requests

from sklearn.metrics import jaccard_score

class Neo4jGraph:
    def __init__(self, config: dict):
        self.log = Log("Neo4jGraph", config)
        self.config = config

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
            process = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return process.stdout.decode('utf-8')

        self.log.info("Removing existing Neo4j container...")
        try:
            run_command('docker rm --force neo4j')
        except subprocess.CalledProcessError:
            self.log.info("No existing container to remove or failed to remove it.")

        self.log.info("Starting a new Neo4j container...")
        run_command('docker run --rm --name neo4j -p 7474:7474 -p 7687:7687 -d -e NEO4J_AUTH=neo4j/password neo4j:latest')

        self.log.info("Waiting for Neo4j to start...")
        while True:
            try:
                response = requests.get("http://localhost:7474")
                if response.status_code == 200:
                    break
            except requests.ConnectionError:
                pass
            sleep(1)

        self.log.info("Neo4j is up and running.")

    @staticmethod
    def create_node_cypher(path: str) -> str:
        return f"CREATE (m:Malware {{path: '{path}'}});\n"

    @staticmethod
    def create_relationship_cypher(path1: str, path2: str, weight: str) -> str:
        return f"MATCH (a:Malware {{path: '{path1}'}}), (b:Malware {{path: '{path2}'}}) CREATE (a)-[:SIMILAR {{weight: {weight}}}]->(b);\n"

    @staticmethod
    def create_node(tx: Transaction, path: str):
        # Old way
        # "CREATE (m:Malware {path: $path}) "
        #             "RETURN elementId(m)"
        # TODO : comment the following and refactor for generalization :
        # properties : dict with keys and values of properties names and values
        # TODO: remove path which is useless
        family = path.split("_")[0]
        query = (
            f"CREATE (n:Malware {{path: $path, Family: '{family}'}})"
            "RETURN n" # do not use id() as it is deprecied
        )
        tx.run(query, path=path)

    # noinspection PyTypeChecker
    @staticmethod
    def create_relationship(tx: Transaction, path1: str, path2: str, weight: float):
        query = (
            "MATCH (a:Malware {path: $path1}), (b:Malware {path: $path2}) "
            "CREATE (a)-[:SIMILAR {weight: $weight}]->(b)"
        )
        tx.run(query, path1=path1, path2=path2, weight=weight)

    def save_graph_as_cypher(self, malware_paths: list[str], malware_attributes, threshold: float, filename: str = "graph.cypher"):
        """
        Save the graph as a Cypher script for later import into Neo4j.
        """
        # TODO: généraliser la fonction
        with open(filename, "w") as cypher_file:
            for path in malware_paths:
                cypher_file.write(Neo4jGraph.create_node_cypher(path))

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
