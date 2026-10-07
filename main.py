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

    def evaluate(self, topk: int):
        """Evaluate every model against the known families (no Neo4j needed)."""
        from evaluation.evaluate import evaluate_all
        evaluate_all(topk=topk)

    def gnn(self, epochs: int):
        """Train/evaluate the GNN on the call graph (needs torch + torch-geometric)."""
        samples_dir = Config().get()["samples"]["directory"]
        from gnn.train import run_gnn  # torch is imported lazily inside run_gnn
        try:
            run_gnn(samples_dir, epochs=epochs)
        except ImportError as e:
            self.log.error(f"GNN needs PyTorch + torch-geometric: {e}. "
                           f"Install with: pip install torch torch-geometric")


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
        help="number of nearest neighbors for --classify / --evaluate (default: 5)"
    )
    parser.add_argument(
        "--evaluate", action="store_true",
        help="evaluate every model against the known families and print metrics"
    )
    parser.add_argument(
        "--gnn", action="store_true",
        help="train/evaluate the GNN (GIN) on the call graph (needs torch + torch-geometric)"
    )
    parser.add_argument(
        "--epochs", type=int, default=150,
        help="training epochs for --gnn (default: 150)"
    )
    args = parser.parse_args()

    m = Main()

    if args.gnn:
        m.gnn(args.epochs)
    elif args.evaluate:
        m.evaluate(args.topk)
    elif args.classify:
        m.classify(args.classify, args.topk)
    else:
        run = m.main
        if args.optimize:
            from memory_profiler import profile
            run = profile(run)
        run()
