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
        # Adjust n_features based on the expected number of unique strings and memory constraints
        self.hasher_string = FeatureHasher(n_features=500, input_type='string')


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
            #temp = self.features[feature].extract(filename)
            #test = self.hash_features(temp)
            #extracted_features[feature] = test

        # Exec Jaccard ensuite donc peut être un tableau ? TODO
        # Ensuite de ce dict on : malware_attributes[filename]
        #for malware1, malware2 in itertools.combinations(malware_paths, 2):
            #jaccard_index = jaccard(malware_attributes[malware1]['Strings'], malware_attributes[malware2]['Strings'])
            # On peut aussi utiliser le Jaccard de Scipy

        return extracted_features

    def hash_features(self, feature_data):
        # TODO : Reprendre le code du FeatureHasher du basic detector

        # features1 = ["hello", "world", "test", "binary"]

        # Transform strings into hashed features
        hashed_features = self.hasher_string.transform([feature_data]).toarray()[0]

        # Convert the hashed vectors to boolean (0 or 1) to represent the presence/absence of a feature
        feature_bool = hashed_features > 0

        # Compute Jaccard similarity later
        return feature_bool
