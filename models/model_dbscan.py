from neo4j import Session

from utils.logger import Log
from utils.config import Config
from sklearn.cluster import DBSCAN
from models.clustering_utils import build_feature_matrix, write_clusters


class DBSCAN_Model:
    """Density-based clustering with Jaccard distance. Unlike K-Means it does
    not need a cluster count and it labels outliers as noise (-1), which maps
    naturally to "unknown family" in an incident-response context."""

    def __init__(self, session: Session, neo4j, redis):
        self.config = Config().get()
        self.log = Log("DBSCAN_Model")
        self.neo4j = neo4j
        self.session = session
        self.redis_storage = redis

    def run(self, malware_attributes: dict, similarity_matrix=None) -> None:
        try:
            X, malwares, _ = build_feature_matrix(malware_attributes)
        except Exception as e:
            self.log.error(f"Error building feature matrix: {e}")
            return

        eps = self.config.get("model", {}).get("dbscan_eps", 0.5)
        min_samples = self.config.get("model", {}).get("dbscan_min_samples", 2)

        try:
            model = DBSCAN(eps=eps, min_samples=min_samples, metric="jaccard")
            labels = model.fit_predict(X)
        except Exception as e:
            self.log.error(f"Error during DBSCAN clustering: {e}")
            return

        n_clusters = len(set(labels) - {-1})
        n_noise = int((labels == -1).sum())

        write_clusters(self.session, self.neo4j, X, malwares, labels, similarity_matrix, self.log)
        self.log.info(f"DBSCAN found {n_clusters} clusters and {n_noise} noise samples (eps={eps}, min_samples={min_samples}).")
