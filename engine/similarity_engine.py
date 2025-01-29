#!/usr/bin/env python3

import os
from utils.neo4j_graph import *
from neo4j import GraphDatabase
from neo4j.exceptions import TransactionError
from features.features_extractor import FeaturesExtractor
from utils.logger import Log
from utils.tools import is_pe_file, filename_from_path
from utils.config import Config
import importlib.util
import inspect

import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
from pickle import dump, load
from engine.redis_storage import RedisStorage
from typing import Callable, Dict

class SimilarityEngine:
    def __init__(self):
        self.config = Config().get()
        self.log = Log("SimilarityEngine")
        self.neo4j = Neo4jGraph()
        self.similarity_matrix = np.zeros((0, 0))
        self.malware_attributes = dict()  # where we'll store the malware's extracted features
        self.redis_storage = RedisStorage()


    def save_extracted_features(self, filename: str) -> None:
        with open(filename, 'wb') as f:
            dump(self.malware_attributes, f)
        self.log.info(f"Extracted features saved to {filename}")

    def load_extracted_features(self, filename: str) -> None:
        with open(filename, 'rb') as f:
            self.malware_attributes = load(f)
        self.log.info(f"Extracted features loaded from {filename}")

    def get_neo4j_driver(self) -> GraphDatabase.driver:
        self.neo4j.check_up()  # Check if Neo4J is up and running
        uri = self.config['neo4j']['uri']
        auth = (self.config['neo4j']['user'], self.config['neo4j']['password'])
        return GraphDatabase.driver(uri, auth=auth)


    def extract_features(self) -> None:
        """
        Extract features from PE binaries in a target directory and store them in a dictionary.
        Parameters
        ----------
        target_directory
        sampling : bool, need to be specified in order to avoid running on all samples at each development iteration

        Returns
        -------

        """
        self.log.info(f"Sampling is set to {self.config['sampling']['do_sampling']}")

        i = 0
        extractor = FeaturesExtractor()
        for root, dirs, paths in os.walk(self.config["samples"]["directory"]):
            for path in paths:
                fullpath = os.path.join(root, path)
                if is_pe_file(fullpath):  # if it is a PE
                    # TODO : add generalization (for ELF and so on)
                    i += 1

                    if not self.config["sampling"]["do_sampling"] or i % self.config["sampling"]["modulo"] == 0:  # Echantillonage pour avoir un max de familles de malwares
                        filename = filename_from_path(fullpath)
                        self.malware_attributes[filename] = extractor.extract_features(fullpath)

    def create_nodes(self, session: GraphDatabase.driver) -> None: # TODO : move to neo4j file
        for key in self.malware_attributes.keys():
            properties = {
                'family': key.split("_")[0],
                'path': key,  # path is necessary for relationships creation
                'color': self.neo4j.get_color_by_label(key.split("_")[0])
            }

            label = key.split("_")[0].replace("-", "_")  # '-' not allowed in nodes names on neo4j
            # TODO : Check that labels doesn't start by a number, not allowed by Neo4j
            try:
                session.execute_write(self.neo4j.create_node, label, properties)
            except TransactionError:
                self.log.error(f"Error creating node for {key}")

    def create_similarity_graph(self) -> None:
        """
        Create a similarity graph for PE binaries in a target directory and export it to a Neo4j database.

        This function scans the target directory for PE binaries, extracts their features,
        builds a similarity graph based on the Jaccard index of extracted strings, and exports the graph to Neo4j.
        """


        # Connect to Neo4j
        driver = self.get_neo4j_driver()

        # Initialize an empty similarity matrix (N x N)
        self.similarity_matrix = np.zeros((len(self.malware_attributes), len(self.malware_attributes)))
        # Optional: set the diagonal to 1 (self-similarity)
        np.fill_diagonal(self.similarity_matrix, 1.0)

        d = driver.session()

        if d:
            try:
                self.create_nodes(d)
                # Create relationships based on a specified model in config
                self.run_sim_model(d)
            finally:
                d.close()
                self.log.info("Graph exported to Neo4j database")
                self.log.info("Neo4J instance is accessible at http://localhost:7474/browser/")

    def dynamic_load_models(self, driver: GraphDatabase.driver, directory: str) -> Dict[str, Callable]:
        instances = {}

        # Traverse the specified directory for models
        for filename in os.listdir(directory):
            if filename.endswith(".py") and filename != "model_runner.py":
                module_name = filename[:-3]  # Remove the '.py' extension
                module_path = os.path.join(directory, filename)

                # Dynamically load the module
                spec = importlib.util.spec_from_file_location(module_name, module_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                # Filter and load only the classes defined in the current module
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)

                    # Ensure it's a class defined in the current module, not an imported class
                    if isinstance(attr, type) and attr.__module__ == module.__name__:
                        init_params = inspect.signature(attr.__init__).parameters
                        required_params = [
                            param for param, details in init_params.items()
                            if details.default == inspect.Parameter.empty and param != 'self'
                        ]

                        # Pass only the parameters expected by the class's constructor
                        instance_args = []
                        # TODO : can be specific to import only the needed parameters to optimize
                        if 'session' in required_params:
                            instance_args.append(driver)
                        if 'neo4j' in required_params:
                            instance_args.append(self.neo4j)
                        if 'redis' in required_params:
                            instance_args.append(self.redis_storage)

                        try:
                            # Instantiate the class with the required arguments
                            instance = attr(*instance_args)
                            instances[f"{attr_name}"] = instance
                        except TypeError as e:
                            self.log.info(f"Skipping {attr_name} - error instantiating class: {str(e)}")
                            continue  # Skip the model if instantiation fails

        return instances


    def run_sim_model(self, driver: GraphDatabase.driver) -> None:
        # Load models, by default all
        dynamic_load_models = self.dynamic_load_models(driver, directory="models/")
        self.log.info(f"Dynamic models imported : {dynamic_load_models}")
        model = dynamic_load_models[self.config["model"]["default"]]

        model.run(self.malware_attributes, self.similarity_matrix)

    def run(self) -> None:

        # Load file pkl
        if self.config["features_cache"]["load"]:
            self.load_extracted_features(self.config["features_cache"]["filename"])
        else:
            self.extract_features()

        self.log.info(f"Found {len(self.malware_attributes)} PE binaries in {self.config['samples']['directory']}")

        # Save to pkl file
        if self.config["features_cache"]["save"]:
            self.save_extracted_features(self.config["features_cache"]["filename"])

        self.create_similarity_graph()

    def similarity_matrix_heatmap(self, filename: str) -> None:
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
                         xticklabels=self.malware_attributes.keys(),
                         yticklabels=self.malware_attributes.keys(),
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
