#!/usr/bin/env python3

from engine.similarity_engine import SimilarityEngine
from time import time
from memory_profiler import profile
from utils.logger import Log
from utils.config import Config


class Main:
    def __init__(self):
        self.log = Log("Main")

    @profile
    def main(self):
        self.log.info(f"Main Started {Config().get()}")
        start_time = time()

        sim = SimilarityEngine()
        sim.run()

        end_time = time()
        elapsed_time = end_time - start_time
        self.log.info(f"Elapsed time: {elapsed_time:.2f} seconds")
        # sim.similarity_matrix_heatmap('strings_and_iat_clean.png')


if __name__ == "__main__":
    # TODO : add argparse to do --debug and --optimize
    m = Main()
    m.main()
