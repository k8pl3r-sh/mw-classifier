#!/usr/bin/python3

"""
Evaluate the clustering models against the known APT1 families.

The clustering calls here mirror those in models/*.py (same config params and
distance), but return labels directly instead of writing to Neo4j, so the
harness needs no database.
"""

import numpy as np
from sklearn.cluster import KMeans, DBSCAN, AgglomerativeClustering
from sklearn.metrics import (
    adjusted_rand_score,
    normalized_mutual_info_score,
    homogeneity_completeness_v_measure,
    silhouette_score,
    pairwise_distances,
)

from utils.config import Config
from utils.logger import Log
from models.clustering_utils import build_feature_matrix
from evaluation.ground_truth import true_labels


def _labelings_internal(X: np.ndarray, config: dict, log) -> dict:
    """Return {model_name: labels_array} for every clustering model."""
    algos = {}
    n_samples = X.shape[0]
    model_cfg = config.get("model", {})
    n_clusters = max(1, min(model_cfg.get("n_clusters", 30), n_samples))

    # Precomputed Jaccard distance matrix (used by agglomerative / HDBSCAN).
    distances = pairwise_distances(X.astype(bool), metric="jaccard")

    algos["KMeans_Model"] = KMeans(n_clusters=n_clusters, random_state=42).fit_predict(X)

    # Unsupervised K-Means: pick k by silhouette over [k_min, k_max].
    k_min = model_cfg.get("k_min", 2)
    k_max = model_cfg.get("k_max", 10)
    best_k, best_score = k_min, -1.0
    for k in range(k_min, min(k_max, n_samples - 1) + 1):
        labels = KMeans(n_clusters=k, random_state=42).fit_predict(X)
        try:
            score = silhouette_score(X, labels)
        except Exception:
            score = -1.0
        if score > best_score:
            best_k, best_score = k, score
    algos["KMeans_Model_Unsupervised"] = KMeans(n_clusters=best_k, random_state=42).fit_predict(X)

    algos["Agglomerative_Model"] = AgglomerativeClustering(
        n_clusters=n_clusters, metric="precomputed", linkage="average"
    ).fit_predict(distances)

    eps = model_cfg.get("dbscan_eps", 0.5)
    min_samples = model_cfg.get("dbscan_min_samples", 2)
    algos["DBSCAN_Model"] = DBSCAN(eps=eps, min_samples=min_samples, metric="jaccard").fit_predict(X)

    try:
        from sklearn.cluster import HDBSCAN
        mcs = model_cfg.get("hdbscan_min_cluster_size", 2)
        algos["HDBSCAN_Model"] = HDBSCAN(min_cluster_size=mcs, metric="precomputed").fit_predict(distances)
    except ImportError:
        log.warn("HDBSCAN unavailable (scikit-learn < 1.3), skipped in evaluation.")

    return algos


def evaluate_clustering(malware_attributes: dict, representation: str = None,
                        features: list = None) -> dict:
    """Compute clustering-quality metrics (vs true families) for each model,
    for a given feature representation (defaults to the config)."""
    log = Log("ClusteringEval")
    config = Config().get()

    X, malwares, _ = build_feature_matrix(malware_attributes, representation=representation, features=features)
    truth = true_labels(malwares)
    n_families = len(set(truth))

    results = {"_n_families": n_families, "_n_samples": len(malwares)}
    for name, labels in _labelings_internal(X, config, log).items():
        labels = np.asarray(labels)
        homogeneity, completeness, v_measure = homogeneity_completeness_v_measure(truth, labels)
        results[name] = {
            "ARI": adjusted_rand_score(truth, labels),
            "NMI": normalized_mutual_info_score(truth, labels),
            "homogeneity": homogeneity,
            "completeness": completeness,
            "v_measure": v_measure,
            "n_clusters": len(set(labels.tolist()) - {-1}),
            "n_noise": int((labels == -1).sum()),
        }
    return results
