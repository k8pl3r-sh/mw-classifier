#!/usr/bin/env python3

from malware_similarity_neo4j.similarity_engine import SimilarityEngine
from utils.tools import load_yml


config = load_yml("config.yml")

sim = SimilarityEngine(config)
sim.run(target_directory="data/", save=True)
