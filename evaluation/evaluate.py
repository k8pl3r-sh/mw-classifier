#!/usr/bin/python3

"""Orchestrate the evaluation harness and render a console report."""

from engine.similarity_engine import SimilarityEngine
from evaluation.clustering_eval import evaluate_clustering
from evaluation.classifier_eval import evaluate_classifier


def _render_classifier(res: dict) -> str:
    lines = []
    sep = "=" * 70
    lines.append(sep)
    lines.append("  CLASSIFIER — leave-one-out family attribution")
    lines.append(sep)
    lines.append(f"  Samples                 : {res['n_samples']}")
    lines.append(f"  Families (singletons)   : {res['n_families']} ({res['n_singletons']} singletons)")
    lines.append(f"  k (neighbors)           : {res['k']}")
    lines.append(f"  Accuracy (all)          : {res['accuracy'] * 100:.1f}%")
    lines.append(f"  Accuracy (>=2 members)  : {res['accuracy_non_singleton'] * 100:.1f}%")
    if res["top_confusions"]:
        lines.append("-" * 70)
        lines.append("  Top misattributions (count  true -> predicted):")
        for count, true_fam, pred in res["top_confusions"]:
            lines.append(f"    {count:>4}  {true_fam} -> {pred}")
    lines.append(sep)
    return "\n".join(lines)


def _render_clustering(res: dict, title: str = "") -> str:
    lines = []
    sep = "=" * 92
    lines.append(sep)
    label = f" [{title}]" if title else ""
    lines.append(f"  CLUSTERING{label} — vs {res['_n_families']} true families over {res['_n_samples']} samples")
    lines.append(sep)
    header = f"  {'model':<28}{'ARI':>7}{'NMI':>7}{'homog':>8}{'compl':>8}{'V':>7}{'#clu':>7}{'#noise':>8}"
    lines.append(header)
    lines.append("-" * 92)
    for name, m in res.items():
        if name.startswith("_"):
            continue
        lines.append(
            f"  {name:<28}{m['ARI']:>7.3f}{m['NMI']:>7.3f}{m['homogeneity']:>8.3f}"
            f"{m['completeness']:>8.3f}{m['v_measure']:>7.3f}{m['n_clusters']:>7}{m['n_noise']:>8}"
        )
    lines.append(sep)
    lines.append("  ARI/NMI/V in [0,1], higher is better. Noise (-1) counts as unassigned.")
    return "\n".join(lines)


# Representations swept by --evaluate so the harness can decide which wins.
_ALL_GROUPS = ["imports", "strings", "imphash", "pe_sections", "rich_header", "pe_resources", "call_graph"]
_SWEEP = [
    ("presence / all features", "presence", None),
    ("hashed / all features", "hashed", None),
    ("hashed / without strings", "hashed", [g for g in _ALL_GROUPS if g != "strings"]),
]


def evaluate_all(topk: int = 5) -> None:
    sim = SimilarityEngine()
    sim.load_corpus()  # features only, no Neo4j
    attributes = sim.malware_attributes

    print(_render_classifier(evaluate_classifier(attributes, k=topk)))

    # Sweep feature representations so one run compares them head-to-head.
    for title, representation, features in _SWEEP:
        res = evaluate_clustering(attributes, representation=representation, features=features)
        print(_render_clustering(res, title))
