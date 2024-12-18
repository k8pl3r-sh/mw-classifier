#!/usr/bin/env python3

import os
from utils.neo4j_graph import *
from neo4j import GraphDatabase
from neo4j.exceptions import TransactionError
from features.features_extractor import FeaturesExtractor
from utils.logger import Log
from utils.tools import is_pe_file, filename_from_path
from engine.minhashcustom import MinHashCustom
from datasketch import MinHashLSH, MinHash
from utils.config import Config

import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
import pickle
from engine.redis_storage import RedisStorage
from models.hnsw_search_nearest_neighbor import HnswSearchNearestNeighbor


class SimilarityEngine:
    def __init__(self):
        self.config = Config().get()
        self.log = Log("SimilarityEngine")
        self.neo4j = Neo4jGraph()
        self.malware_paths = []  # where we'll store the malware file paths
        self.similarity_matrix = np.zeros((0, 0))
        self.malware_attributes = dict()  # where we'll store the malware's extracted features
        self.minhash_custom = MinHashCustom()
        self.minhash = MinHash(num_perm=128)

        # WORK :
        self.redis_storage = RedisStorage()
        self.hnsw_search = HnswSearchNearestNeighbor()

    def save_extracted_features(self, filename: str):
        with open(filename, 'wb') as fh:
            pickle.dump((self.malware_attributes, self.malware_paths), fh)
        self.log.info(f"Extracted features saved to {filename}")

    def load_extracted_features(self, filename: str):
        with open(filename, 'rb') as fh:
            self.malware_attributes, self.malware_paths = pickle.load(fh)
        self.log.info(f"Extracted features loaded from {filename}")

    def get_neo4j_driver(self):
        self.neo4j.check_up()  # Check if Neo4J is up and running
        uri = self.config['neo4j']['uri']
        auth = (self.config['neo4j']['user'], self.config['neo4j']['password'])
        return GraphDatabase.driver(uri, auth=auth)

    @staticmethod
    def close_neo4j_driver(driver):
        driver.close()

    def extract_features(self, target_directory: str, sampling: bool):
        """
        Extract features from PE binaries in a target directory and store them in a dictionary.
        Parameters
        ----------
        target_directory
        sampling : bool, need to be specified in order to avoid running on all samples at each development iteration

        Returns
        -------

        """
        self.log.info(f"Sampling is set to {sampling}")

        i = 0
        extractor = FeaturesExtractor(self.config)
        for root, dirs, paths in os.walk(target_directory):
            for path in paths:
                fullpath = os.path.join(root, path)
                if is_pe_file(fullpath):  # if it is a PE
                    # TODO : add generalization (for ELF and so on)
                    i += 1

                    if not sampling or i % self.config["sampling"]["modulo"] == 0:  # Echantillonage pour avoir un max de familles de malwares
                        filename = filename_from_path(fullpath)
                        # INFO : malware_path : filename can't start with a number for Neo4J
                        self.malware_paths.append(filename)  # TODO : check use because key of another dict
                        self.malware_attributes[filename] = extractor.extract_features(fullpath)

    def create_nodes(self, session): # TODO : move to neo4j file
        for path in self.malware_paths:
            properties = {
                'family': path.split("_")[0],
                'path': path,  # path is necessary for relationships creation
                'color': self.neo4j.get_color_by_label(path.split("_")[0])
            }

            label = path.split("_")[0].replace("-", "_")  # '-' not allowed in nodes names on neo4j
            try:
                session.execute_write(self.neo4j.create_node, label, properties)
            except TransactionError:
                self.log.error(f"Error creating node for {path}")

    def create_similarity_graph(self):
        """
        Create a similarity graph for PE binaries in a target directory and export it to a Neo4j database.

        This function scans the target directory for PE binaries, extracts their features,
        builds a similarity graph based on the Jaccard index of extracted strings, and exports the graph to Neo4j.

        Args:
            threshold (float, optional): The Jaccard index threshold for creating edges in the graph. Default is 0.8.
            save (bool, optional): Whether to save the graph as a Cypher script. Default is False.
        """


        # Connect to Neo4j
        driver = self.get_neo4j_driver()

        # Initialize an empty similarity matrix (N x N)
        self.similarity_matrix = np.zeros((len(self.malware_paths), len(self.malware_paths)))
        # Optional: set the diagonal to 1 (self-similarity)
        np.fill_diagonal(self.similarity_matrix, 1.0)

        with driver.session() as session:

            # Create nodes
            self.create_nodes(session)

            # Create relationships based on a specified model in config
            self.run_sim_model(session)

        SimilarityEngine.close_neo4j_driver(driver)
        self.log.info("Graph exported to Neo4j database")

        #if save:
        #self.neo4j.save_graph_as_cypher(self.malware_paths, self.malware_attributes, self.config["model"]["threshold"])
        self.log.info("Neo4J instance is accessible at http://localhost:7474/browser/")

    def search_similarities_lsh(self, session):
        """
        Optimized method to find relationships between malware samples using LSH to avoid pairwise comparisons.
        """
        # Initialize LSH
        # Doc : http://ekzhu.com/datasketch/lsh.html
        try:
            lsh = MinHashLSH(threshold=self.config["model"]["threshold"], num_perm=128)
        except ValueError:
            self.log.error(" The number of bands are too small (b < 2)")
            return
        minhashes = {}

        # Generate MinHash signatures using the datasketch MinHash object and insert them into LSH
        for malware, attributes in self.malware_attributes.items():
            minhash = MinHash(num_perm=128)

            # Combine all features' MinHash signatures for the malware
            for feature_name, feature_set in attributes.items():
                for idx, is_true in enumerate(feature_set):
                    if is_true:
                        minhash.update(str(idx).encode('utf8'))

            # Store the MinHash signature and insert it into the LSH index
            minhashes[malware] = minhash
            lsh.insert(malware, minhash)

            # WORK: Store the MinHash signature in Redis
            try:
                self.redis_storage.store_minhash_signature(malware, minhash)
            except Exception as e:
                self.log.error(f"Error {e} : Probably Redis docker not started via docker-compose up -d")
            # WORK: Add the MinHash signature to the HNSW index
            # self.hnsw_search.add_signature(malware, minhash)

        # Now query the LSH for similar malwares and create relationships
        for malware1, minhash1 in minhashes.items():
            similar_malwares = lsh.query(minhash1)

            for malware2 in similar_malwares:
                if malware1 != malware2:
                    # Ensure only one relationship is created by always using the lexicographically smaller malware first
                    if malware1 < malware2:
                        # Compute the approximate Jaccard similarity if needed
                        jaccard_indexes = []

                        union_keys = set(self.malware_attributes[malware1].keys()).union(
                            set(self.malware_attributes[malware2].keys()))  # compilation of all features names of both binaries

                        for feature_name in union_keys:
                            # TODO : can be syntax optimized with if/else ? Warn of Key error if not found
                            m1_f = self.malware_attributes.get(malware1, {}).get(feature_name, [])
                            m2_f = self.malware_attributes.get(malware2, {}).get(feature_name, [])

                            if len(m1_f) == 0:  # features need to have the same length to be compared
                                m1_f = [None] * len(m2_f)
                            elif len(m2_f) == 0:
                                m2_f = [None] * len(m1_f)

                            # TODO : have to replace the following line by minhash1.jaccard(minhash2), here it is 2 hashed lists
                            feature_similarity_index = self.minhash_custom.compute_minhash_similarity(m1_f, m2_f)
                            jaccard_indexes.append(feature_similarity_index)

                        jaccard_index = np.mean(jaccard_indexes)  # mean of all features to have a global similarity index

                        if jaccard_index > self.config["model"]["threshold"]:
                            session.execute_write(self.neo4j.create_relationship, malware1, malware2, jaccard_index)

                        # Update the similarity matrix
                        index_1 = self.malware_paths.index(malware1)
                        index_2 = self.malware_paths.index(malware2)
                        self.similarity_matrix[index_1, index_2] = jaccard_index
                        self.similarity_matrix[index_2, index_1] = jaccard_index

    def run_sim_model(self, session):
        # TODO : load model here instead of LSH
        self.search_similarities_lsh(session=session)

    def run(self):
        self.neo4j.start_neo4j_container()

        # Load file pkl
        if self.config["features_cache"]["load"]:
            self.load_extracted_features(self.config["features_cache"]["filename"])
        else:
            self.extract_features(self.config["samples"]["directory"], sampling=self.config["sampling"]["do_sampling"]) # TODO : move sampling arg to config file

        self.log.debug(f"Malware paths found {self.malware_paths}")
        self.log.info(f"Found {len(self.malware_paths)} PE binaries in {self.config['samples']['directory']}")

        # Save to pkl file
        if self.config["features_cache"]["save"]:
            self.save_extracted_features(self.config["features_cache"]["filename"])

        self.create_similarity_graph()

    def similarity_matrix_heatmap(self, filename: str):
        """
        Convert the similarity matrix into a heatmap graphic and save it to a file.

        Parameters
        ----------
        filename : str name of the file to create

        Returns
        -------

        """
        self.log.info("Generating heatmap...")
        filename = self.config["graphics"]["path"] + filename
        # Set up the matplotlib figure
        plt.figure(figsize=(25, 25), dpi=300)

        # Create a heatmap using seaborn
        ax = sns.heatmap(self.similarity_matrix,
                         xticklabels=self.malware_paths,
                         yticklabels=self.malware_paths,
                         cmap="YlGnBu",  # You can change the color map here
                         annot=False,  # Set to True to display the Jaccard index values, but makes it harder to read
                         fmt=".2f")  # Format the numbers to 2 decimal places

        # Add labels and title
        ax.set_title("Malware Similarity Matrix (Jaccard Index)")
        plt.xlabel("Malware Samples")
        plt.ylabel("Malware Samples")
        plt.xticks(rotation=90, fontsize=8)
        plt.yticks(rotation=0, fontsize=8)

        # Save the heatmap
        # Avoid to display it to its size
        plt.savefig(filename, format='png', bbox_inches='tight')
        self.log.info(f"Saved heatmap to {filename}")
