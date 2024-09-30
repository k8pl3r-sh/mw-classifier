#!/usr/bin/python3

import os
from utils.logger import Log
import importlib
from sklearn.feature_extraction import FeatureHasher

import mmh3
import numpy as np
from malware_similarity_neo4j.minhashcustom import MinHashCustom as MinHash

current_file_path = os.path.abspath(__file__)  # Absolute path of the current file
FEATURES_FOLDER = os.path.abspath(os.path.dirname(current_file_path))


class FeaturesExtractor:
    features: object

    def __init__(self, config: dict):
        self.config = config
        self.log = Log("FeaturesExtractor", config)
        self.features = self._load_features()
        # Adjust n_features based on the expected number of unique strings and memory constraints
        self.hasher_string = FeatureHasher(n_features=self.config['sklearn']['n_features'], input_type='dict')
        # n_features : number of features to hash : default : 1048576 : 2**20
        # input_typestr, default=’dict’, choices=[‘dict’, ‘pair’, ‘string’]
        self.minhash = MinHash(num_hashes=128)

    def _load_features(self) -> list[object]:
        features_files = [file for file in os.listdir(FEATURES_FOLDER) if file.endswith(".py")]
        features_files.remove(os.path.basename(__file__))  # remove features_extractor.py
        # TODO : way to select features to load by specifying them in the config file

        features = {}
        for file in features_files:

            file_path = os.path.join(FEATURES_FOLDER, file)
            file = file.replace(".py", "")
            feature_name = ''.join(word.title() for word in file.split('_'))  # snake_deluxe -> SnakeDeluxe

            spec = importlib.util.spec_from_file_location(feature_name, file_path)
            feature = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(feature)

            feature_class = getattr(feature, feature_name)
            if feature_class:
                features[feature_name] = feature_class(self.config)
        self.log.info(f"Loaded {len(features)} features : {features}")
        return features

    def extract_features(self, filename: str) -> dict[str, set]:
        """
        Extract features from a given file and hash them using mmh3
        Parameters
        ----------
        filename: filename path from which we extract features

        Returns
        -------
        """
        # Liste de fichiers, liste de features strings -> convert pour les objects
        # retourne dict avec 'feature': {dict retourné}
        extracted_features = {}

        # TODO : refactored to manage dict of key : values to use one feature extractor to extract multiple features

        for feature in self.features:

            # Ici de l'objet 'feature' on appelle sa méthode d'extraction qui retourne un set
            temp = self.features[feature].extract(filename)
            # must hash a set
            for element in temp.keys():
                hashed = self.hash_features(temp[element])
                minhashes = self.minhash.generate_minhash_signature(hashed)
            # need to change here to have multiple features
                extracted_features[element] = minhashes

        return extracted_features

    def hash_features(self, feature_data: set):
        """
        Hash the extracted featues using mmh3
        Parameters
        ----------
        feature_data : set
            A set of features (strings) to be hashed.

        Returns
        -------
        np.ndarray
            A boolean array indicating the presence (1) or absence (0) of features.
        """
        # TODO : Reprendre le code du FeatureHasher du basic detector

        # features1 = ["hello", "world", "test", "binary"]

        # Transform strings into hashed features

        # Convert set to dict (depuis, ça fonctionne pas
        # Convert set to dictionary format for hashing (with values set to 1)
        # dict_input = {item: 1 for item in feature_data}
        # hashed_features = self.hasher_string.transform([dict_input]).toarray()[0]

        # Convert the hashed vectors to boolean (0 or 1) to represent the presence/absence of a feature
        # feature_bool = hashed_features > 0

        # Compute Jaccard similarity later
        # return feature_bool

        # UPDATED :
        # Define a fixed length for your hashed feature vector
        vector_length = 1024  # You can adjust this size based on your requirements

        # Create an empty binary vector to represent the presence/absence of hashed features
        feature_vector = np.zeros(vector_length, dtype=bool)

        # Hash each feature using mmh3 and map the hash value to a position in the binary vector
        # for feature in feature_data: It is a set not a dict right now
        for feature in feature_data:
            # Ensure that the feature is a string (or convert it to string)
            feature = str(feature)  # check that the string is a string

            # Use mmh3 to hash the feature and get a positive integer (32-bit)
            hashed_value = mmh3.hash(feature)
            # mmh3.hash(): Returns a 32-bit integer hash.
            # mmh3.hash128(): Returns a 128-bit hash (if a larger hash space is needed).

            # Map the hashed value to an index in the vector by using modulo operation
            index = hashed_value % vector_length

            # Set the corresponding index in the binary vector to 1 (feature is present)
            feature_vector[index] = True

        return feature_vector
