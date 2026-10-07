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

    def classify(self, filepath: str, topk: int):
        """Attribute a single binary to the nearest known family and print a report."""
        from engine.classifier import Classifier
        from utils.report import render_classification

        sim = SimilarityEngine()
        sim.load_corpus()  # features only, no Neo4j needed
        classifier = Classifier(sim.malware_attributes)
        result = classifier.classify_file(filepath, k=topk)
        print(render_classification(result))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Malware similarity engine")
    parser.add_argument(
        "--optimize", action="store_true",
        help="run under memory_profiler to report per-line memory usage"
    )
    parser.add_argument(
        "--classify", metavar="FILE",
        help="classify a single binary against the corpus and print a report (no graph build)"
    )
    parser.add_argument(
        "--topk", type=int, default=5,
        help="number of nearest neighbors to report with --classify (default: 5)"
    )
    args = parser.parse_args()

    m = Main()

    if args.classify:
        m.classify(args.classify, args.topk)
    else:
        run = m.main
        if args.optimize:
            from memory_profiler import profile
            run = profile(run)
        run()
