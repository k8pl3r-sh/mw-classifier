from neo4j import Session

from utils.logger import Log
from utils.config import Config
from models.clustering_utils import build_feature_matrix, write_clusters


class HDBSCAN_Model:
    """Hierarchical DBSCAN: density-based clustering that does not require eps.
    It handles variable-density families and labels outliers as noise (-1).

    HDBSCAN lives in sklearn.cluster since scikit-learn 1.3; the import is lazy
    so loading this module never breaks on older scikit-learn versions."""

    def __init__(self, session: Session, neo4j, redis):
        self.config = Config().get()
        self.log = Log("HDBSCAN_Model")
        self.neo4j = neo4j
        self.session = session
        self.redis_storage = redis

    def run(self, malware_attributes: dict, similarity_matrix=None) -> None:
        try:
            from sklearn.cluster import HDBSCAN
            from sklearn.metrics import pairwise_distances
        except ImportError:
            self.log.error("HDBSCAN requires scikit-learn >= 1.3; skipping this model.")
            return

        try:
            X, malwares, _ = build_feature_matrix(malware_attributes)
        except Exception as e:
            self.log.error(f"Error building feature matrix: {e}")
            return

        min_cluster_size = self.config.get("model", {}).get("hdbscan_min_cluster_size", 2)

        try:
            distances = pairwise_distances(X.astype(bool), metric="jaccard")
            model = HDBSCAN(min_cluster_size=min_cluster_size, metric="precomputed")
            labels = model.fit_predict(distances)
        except Exception as e:
            self.log.error(f"Error during HDBSCAN clustering: {e}")
            return

        n_clusters = len(set(labels) - {-1})
        n_noise = int((labels == -1).sum())

        write_clusters(self.session, self.neo4j, X, malwares, labels, similarity_matrix, self.log)
        self.log.info(f"HDBSCAN found {n_clusters} clusters and {n_noise} noise samples (min_cluster_size={min_cluster_size}).")
