#!/usr/bin/env python3

from malware_similarity_neo4j.similarity_engine import SimilarityEngine
from utils.tools import load_yml
from time import time
from memory_profiler import profile
from utils.logger import Log


class Main:
    def __init__(self):
        self.config = load_yml("config.yml")
        self.log = Log("Main", self.config)

    @profile
    def main(self):
        start_time = time()

        sim = SimilarityEngine(self.config)
        sim.run()
        # SAMPLES/ransomware_notes-main

        end_time = time()
        elapsed_time = end_time - start_time
        self.log.info(f"Elapsed time: {elapsed_time:.2f} seconds")
        # sim.similarity_matrix_heatmap('strings_and_iat_clean.png')


if __name__ == "__main__":
    # TODO : add argparse to do --debug and --optimize
    m = Main()
    m.main()
