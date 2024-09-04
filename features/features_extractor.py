#!/usr/bin/python3

import os
from utils.logger import Log
import importlib
from sklearn.feature_extraction import FeatureHasher

current_file_path = os.path.abspath(__file__)  # Absolute path of the current file
FEATURES_FOLDER = os.path.abspath(os.path.dirname(current_file_path))


class FeaturesExtractor:
    features: object


    def __init__(self, config: dict):
        self.config = config
        self.log = Log("FeaturesExtractor", config)
        self.features = self.load_features()


    def load_features(self) -> list[object]:
        features_files = [file for file in os.listdir(FEATURES_FOLDER) if file.endswith(".py")]
        features_files.remove(os.path.basename(__file__))  # remove features_extractor.py

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
        Extract features from a given file
        Parameters
        ----------
        filename: filename path from which we extract features

        Returns
        -------

        """
        # Liste de fichiers, liste de features strings -> convert pour les objects
        # retourne dict avec 'feature': {dict retourné}
        extracted_features = {}

        for feature in self.features:
            extracted_features[feature] = self.features[feature].extract(filename)

        return extracted_features

    def hash_features(self):
        # TODO : Reprendre le code du FeatureHasher du basic detector
        self.hasher = FeatureHasher(n_features=15000, input_type='string')
        features1 = ["hello", "world", "test", "binary"]

        # Transform strings into hashed features
        hashed_binary_1 = self.hasher.transform([features1]).toarray()[0]

        # Convert the hashed vectors to boolean (0 or 1) to represent the presence/absence of a feature
        binary_1_bool = hashed_binary_1 > 0

        # Compute Jaccard similarity

        ...
