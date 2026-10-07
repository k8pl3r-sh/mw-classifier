#!/usr/bin/python3

"""
Leave-one-out evaluation of the Classifier (family attribution).

For every corpus sample, classify it against all the *others* and check whether
the predicted family matches the true family. This is the metric that matters
for the incident-response use case.
"""

from collections import Counter

from utils.logger import Log
from engine.classifier import Classifier
from evaluation.ground_truth import family_of


def evaluate_classifier(malware_attributes: dict, k: int = 5) -> dict:
    log = Log("ClassifierEval")
    clf = Classifier(malware_attributes)

    family_sizes = Counter(family_of(name) for name in clf.names)
    total = correct = 0
    total_ns = correct_ns = 0  # ns = families with >= 2 members (LOO is possible)
    confusion = Counter()

    for name in clf.names:
        true_family = family_of(name)
        result = clf.classify_corpus_member(name, k=k)
        predicted = result["predicted_family"]

        total += 1
        if predicted == true_family:
            correct += 1
        if predicted != true_family:
            confusion[(true_family, predicted)] += 1

        # A singleton family can never be recovered by LOO (no sibling left),
        # so we also report accuracy restricted to families with >= 2 members.
        if family_sizes[true_family] >= 2:
            total_ns += 1
            if predicted == true_family:
                correct_ns += 1

    n_singletons = sum(1 for _, c in family_sizes.items() if c == 1)
    log.info(f"Leave-one-out over {total} samples done.")

    return {
        "k": k,
        "n_samples": total,
        "n_families": len(family_sizes),
        "n_singletons": n_singletons,
        "accuracy": correct / total if total else 0.0,
        "accuracy_non_singleton": correct_ns / total_ns if total_ns else 0.0,
        "top_confusions": sorted(
            ((count, t, p) for (t, p), count in confusion.items()),
            reverse=True
        )[:10],
    }
