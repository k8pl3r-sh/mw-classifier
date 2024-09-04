#!/usr/bin/env python3

from malware_similarity_neo4j.similarity_engine import SimilarityEngine
from utils.tools import load_yml


if __name__ == "__main__":
    config = load_yml("config.yml")
    sim = SimilarityEngine(config)
    sim.run(target_directory="SAMPLES/APT1_MALWARE_FAMILIES/", save=True)
