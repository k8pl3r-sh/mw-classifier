"""
Shared helpers for clustering models (feature matrix + Neo4j export).

This module defines no model class, so the engine's dynamic model loader
imports it without registering anything to run.
"""

import numpy as np
import mmh3

from utils.config import Config

HASH_DIM_DEFAULT = 16384  # 2**14 columns for the hashing trick

# Single-key features; everything else (per-DLL keys of static_iat, plus the
# ELF/Mach-O 'imported_functions'/'libraries' keys) is grouped as "imports".
_SINGLE_KEY_FEATURES = {
    "strings", "call_graph", "imphash", "pe_sections", "rich_header", "pe_resources",
}


def feature_group(key: str) -> str:
    """Map a raw feature key to a logical group usable in config selection."""
    return key if key in _SINGLE_KEY_FEATURES else "imports"


def build_feature_matrix(malware_attributes: dict, representation: str = None,
                         features: list = None, hash_dim: int = None):
    """
    Build the clustering feature matrix.

    representation:
      - "presence" : one binary column per (included) feature key, 1 if present.
                     Low-dimensional, dominated by the structured import keys.
      - "hashed"   : hashing trick, one binary column per hashed token (prefixed
                     with its feature name). Exposes token *content* but is
                     sensitive to verbose/noisy features and hash collisions.

    features: list of feature groups to INCLUDE (see feature_group); empty/None
      means all. E.g. exclude the noisy strings with
      ["imports","imphash","pe_sections","rich_header","pe_resources","call_graph"].

    Falls back to the ``clustering`` section of the config when args are None.

    Returns (X, malwares, columns) where columns is the key list ("presence") or
    None ("hashed").
    """
    cfg = Config().get().get("clustering", {})
    if representation is None:
        representation = cfg.get("representation", "presence")
    if features is None:
        features = cfg.get("features", []) or []
    if hash_dim is None:
        hash_dim = cfg.get("hash_dim", HASH_DIM_DEFAULT)

    allowed = set(features) if features else None  # None => all groups

    def included(key: str) -> bool:
        return allowed is None or feature_group(key) in allowed

    malwares = list(malware_attributes.keys())

    if representation == "hashed":
        X = np.zeros((len(malwares), hash_dim), dtype=np.uint8)
        for i, mw in enumerate(malwares):
            for key, tokens in malware_attributes[mw].items():
                if not included(key):
                    continue
                for token in tokens:
                    idx = mmh3.hash(f"{key}:{token}") % hash_dim
                    X[i, idx] = 1
        return X, malwares, None

    # "presence": one binary column per included feature key
    feature_list = sorted({
        key for attrs in malware_attributes.values() for key in attrs.keys() if included(key)
    })
    col = {key: j for j, key in enumerate(feature_list)}
    X = np.zeros((len(malwares), len(feature_list)), dtype=np.uint8)
    for i, mw in enumerate(malwares):
        for key, tokens in malware_attributes[mw].items():
            if included(key) and tokens:
                X[i, col[key]] = 1
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
