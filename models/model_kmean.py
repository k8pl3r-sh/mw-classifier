import numpy as np
from sklearn.cluster import KMeans
from neo4j import Session

from utils.logger import Log
from utils.config import Config


class KMeans_Model:
    def __init__(self, session: Session, neo4j, redis):
        self.config = Config().get()
        self.log = Log("KMeans_Model")
        self.neo4j = neo4j
        self.session = session
        self.redis_storage = redis

    def _build_feature_matrix(self, malware_attributes: dict) -> (np.ndarray, list, list):
        """
        Construct a binary feature matrix for clustering.

        Returns:
            X: ndarray of shape (n_samples, n_features)
            malwares: list of malware names in order
            feature_list: list of feature keys in order
        """
        feature_list = sorted({
            feat for attrs in malware_attributes.values() for feat in attrs.keys()
        })
        malwares = list(malware_attributes.keys())
        X = np.zeros((len(malwares), len(feature_list)), dtype=int)
        for i, mw in enumerate(malwares):
            attrs = malware_attributes[mw]
            for j, feat in enumerate(feature_list):
                vals = attrs.get(feat, [])
                X[i, j] = 1 if any(vals) else 0
        return X, malwares, feature_list

    def run(self, malware_attributes: dict, similarity_matrix=None) -> None:
        try:
            X, malwares, feature_list = self._build_feature_matrix(malware_attributes)
        except Exception as e:
            self.log.error(f"Error building feature matrix: {e}")
            return

        n_clusters = self.config.get("model", {}).get("n_clusters", 33)
        if n_clusters < 1 or n_clusters > len(malwares):
            self.log.warn(f"Invalid n_clusters={n_clusters}, resetting to 1")
            n_clusters = 1

        try:
            kmeans = KMeans(n_clusters=n_clusters, random_state=42)
            labels = kmeans.fit_predict(X)
        except Exception as e:
            self.log.error(f"Error during K-Means clustering: {e}")
            return

        if self.config["database"].get("redis", False):
            try:
                self.redis_storage.store_centroids(kmeans.cluster_centers_)
            except Exception as e:
                self.log.error(f"Redis store centroids failed: {e}")

        cluster_map = {}
        for idx, mw in enumerate(malwares):
            cluster_id = int(labels[idx])
            cluster_map.setdefault(cluster_id, []).append(mw)

        # Create the Cluster nodes once each (idempotent MERGE, no duplicates).
        for cluster_id in cluster_map:
            try:
                self.session.execute_write(self.neo4j.merge_cluster_node, cluster_id=cluster_id)
            except Exception as e:
                self.log.error(f"Neo4j Cluster node write error for {cluster_id}: {e}")

        # Link each malware to its cluster with a BELONGS_TO relationship.
        for cluster_id, malware_list in cluster_map.items():
            for mw in malware_list:
                try:
                    self.session.execute_write(
                        self.neo4j.create_membership,
                        malware_path=mw,
                        cluster_id=cluster_id,
                        weight=1.0
                    )
                except Exception as e:
                    self.log.error(f"Neo4j membership write error for {mw}@{cluster_id}: {e}")

        # Create SIMILAR relationships between malware in the same cluster,
        # and fill the similarity matrix (1.0 for same-cluster pairs).
        index_of = {mw: idx for idx, mw in enumerate(malwares)}
        for cluster_id, malware_list in cluster_map.items():
            for i in range(len(malware_list)):
                for j in range(i + 1, len(malware_list)):
                    if similarity_matrix is not None:
                        a, b = index_of[malware_list[i]], index_of[malware_list[j]]
                        similarity_matrix[a, b] = 1.0
                        similarity_matrix[b, a] = 1.0
                    try:
                        self.session.execute_write(
                            self.neo4j.create_relationship,
                            path1=malware_list[i],
                            path2=malware_list[j],
                            weight=1.0  # full similarity within cluster
                        )
                    except Exception as e:
                        self.log.error(f"Neo4j SIMILAR write error between {malware_list[i]} and {malware_list[j]}: {e}")

        self.log.info(f"K-Means clustering assigned {len(malwares)} samples into {n_clusters} families.")