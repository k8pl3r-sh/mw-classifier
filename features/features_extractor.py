#!/usr/bin/python3

import os
from utils.logger import Log
import importlib
from utils.config import Config

current_file_path = os.path.abspath(__file__)  # Absolute path of the current file
FEATURES_FOLDER = os.path.abspath(os.path.dirname(current_file_path))


class FeaturesExtractor:
    features: object

    def __init__(self):
        self.config = Config().get()
        self.log = Log("FeaturesExtractor")
        self.features = self._load_features()

    def _load_features(self) -> dict[str, object]:
        features_files = [file for file in os.listdir(FEATURES_FOLDER) if file.endswith(".py")]
        features_files.remove(os.path.basename(__file__))  # remove features_extractor.py
        # TODO : way to select features to load by specifying them in the config file

        features = {}
        for file in features_files:

            file_path = os.path.join(FEATURES_FOLDER, file)
            file = file.replace(".py", "")
            feature_name = ''.join(word.title() for word in file.split('_'))  # CamelCase :snake_deluxe -> SnakeDeluxe

            spec = importlib.util.spec_from_file_location(feature_name, file_path)
            feature = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(feature)

            feature_class = getattr(feature, feature_name)
            if feature_class:
                features[feature_name] = feature_class()
        self.log.info(f"Loaded {len(features)} features : {features}")
        return features

    def extract_features(self, filename: str) -> dict[str, set]:
        """
        Extract raw feature tokens from a file.

        Returns a mapping ``{feature_name: set(tokens)}`` where tokens are the
        raw strings / imported function names. No hashing or min-hashing is
        performed here: each model builds the representation it needs (e.g. a
        datasketch ``MinHash`` in ``LSH_Model``) directly from these token sets.

        Parameters
        ----------
        filename : str
            Path of the binary from which features are extracted.
        """
        extracted_features = {}

        for feature in self.features:
            # Each extractor returns a dict {element_name: iterable_of_tokens}
            # (e.g. {'strings': {...}} or {'KERNEL32.dll': [...], ...}).
            temp = self.features[feature].extract(filename)
            if not temp:
                continue
            for element, tokens in temp.items():
                extracted_features[element] = set(tokens)

        return extracted_features
