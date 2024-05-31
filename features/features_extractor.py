#!/usr/bin/python3

import os
from utils.logger import Log
import importlib

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
        # Liste de fichiers, liste de features strings -> convert pour les objects
        # retourne dict avec 'feature': {dict retourné}
        extracted_features = {}

        for feature in self.features:
            extracted_features[feature] = self.features[feature].extract(filename)

        return extracted_features
