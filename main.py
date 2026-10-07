#!/usr/bin/env python3

import argparse
from time import time
from engine.similarity_engine import SimilarityEngine
from utils.logger import Log
from utils.config import Config


class Main:
    def __init__(self):
        self.log = Log("Main")

    def main(self):
        self.log.info(f"Main Started {Config().get()}")
        start_time = time()

        sim = SimilarityEngine()
        sim.run()

        sim.similarity_matrix_heatmap('similarity_matrix.png')

        end_time = time()
        elapsed_time = end_time - start_time
        self.log.info(f"Elapsed time: {elapsed_time:.2f} seconds")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Malware similarity engine")
    parser.add_argument(
        "--optimize", action="store_true",
        help="run under memory_profiler to report per-line memory usage"
    )
    args = parser.parse_args()

    m = Main()
    run = m.main
    if args.optimize:
        from memory_profiler import profile
        run = profile(run)
    run()
