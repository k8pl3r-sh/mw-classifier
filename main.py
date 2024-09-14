#!/usr/bin/env python3

from malware_similarity_neo4j.similarity_engine import SimilarityEngine
from utils.tools import load_yml
from time import time


if __name__ == "__main__":
    start_time = time()

    config = load_yml("config.yml")
    sim = SimilarityEngine(config)
    sim.run(target_directory="SAMPLES/APT1_MALWARE_FAMILIES/", save=False)

    end_time = time()
    elapsed_time = end_time - start_time
    print(f"Elapsed time: {elapsed_time:.2f} seconds")
    # sim.similarity_matrix_heatmap('similarity_matrix_test.png')
