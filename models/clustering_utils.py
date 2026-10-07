"""
Shared helpers for clustering models (feature matrix + Neo4j export).

This module defines no model class, so the engine's dynamic model loader
imports it without registering anything to run.
"""

import numpy as np


def build_feature_matrix(malware_attributes: dict):
    """
    Build a binary presence/absence feature matrix from the token sets.

    Returns
    -------
    X : np.ndarray of shape (n_samples, n_features), dtype int (0/1)
    malwares : list[str]  malware names, row order of X
    feature_list : list[str]  feature keys, column order of X
    """
    feature_list = sorted({
        feat for attrs in malware_attributes.values() for feat in attrs.keys()
    })
    malwares = list(malware_attributes.keys())
    X = np.zeros((len(malwares), len(feature_list)), dtype=int)
    for i, mw in enumerate(malwares):
        attrs = malware_attributes[mw]
        for j, feat in enumerate(feature_list):
            if attrs.get(feat):
                X[i, j] = 1
    return X, malwares, feature_list


def _jaccard(xa: np.ndarray, xb: np.ndarray) -> float:
    union = int((xa | xb).sum())
    return float((xa & xb).sum() / union) if union else 0.0


def write_clusters(session, neo4j, X, malwares, labels, similarity_matrix=None, log=None) -> dict:
    """
    Export clustering results to Neo4j: a Cluster node per label, a BELONGS_TO
    relationship per sample, and intra-cluster SIMILAR edges weighted by the
    real Jaccard of the binary feature vectors. Label -1 is treated as noise
    (no cluster, no edges) so DBSCAN/HDBSCAN outliers are not forced together.

    Returns the {cluster_id: [malware, ...]} map (noise excluded).
    """
    cluster_map = {}
    for idx, mw in enumerate(malwares):
        cid = int(labels[idx])
        if cid == -1:
            continue  # noise / unassigned
        cluster_map.setdefault(cid, []).append(mw)

    # Cluster nodes (idempotent)
    for cid in cluster_map:
        try:
            session.execute_write(neo4j.merge_cluster_node, cluster_id=cid)
        except Exception as e:
            if log:
                log.error(f"Neo4j Cluster node write error for {cid}: {e}")

    # Membership
    for cid, members in cluster_map.items():
        for mw in members:
            try:
                session.execute_write(neo4j.create_membership, malware_path=mw, cluster_id=cid, weight=1.0)
            except Exception as e:
                if log:
                    log.error(f"Neo4j membership write error for {mw}@{cid}: {e}")

    # Intra-cluster SIMILAR edges, weighted by real Jaccard
    index_of = {mw: i for i, mw in enumerate(malwares)}
    for cid, members in cluster_map.items():
        for i in range(len(members)):
            for j in range(i + 1, len(members)):
                a, b = index_of[members[i]], index_of[members[j]]
                weight = _jaccard(X[a].astype(bool), X[b].astype(bool))
                if similarity_matrix is not None:
                    similarity_matrix[a, b] = weight
                    similarity_matrix[b, a] = weight
                if weight > 0.0:
                    try:
                        session.execute_write(neo4j.create_relationship, members[i], members[j], weight)
                    except Exception as e:
                        if log:
                            log.error(f"Neo4j SIMILAR write error between {members[i]} and {members[j]}: {e}")

    return cluster_map
