from neo4j import Session

from utils.logger import Log
from utils.config import Config
from sklearn.cluster import AgglomerativeClustering
from sklearn.metrics import pairwise_distances
from models.clustering_utils import build_feature_matrix, write_clusters


class Agglomerative_Model:
    """Hierarchical (agglomerative) clustering on the binary feature matrix,
    using Jaccard distance. Like K-Means it needs a target number of clusters,
    but it builds a nested merge structure instead of centroids."""

    def __init__(self, session: Session, neo4j, redis):
        self.config = Config().get()
        self.log = Log("Agglomerative_Model")
        self.neo4j = neo4j
        self.session = session
        self.redis_storage = redis

    def run(self, malware_attributes: dict, similarity_matrix=None) -> None:
        try:
            X, malwares, _ = build_feature_matrix(malware_attributes)
        except Exception as e:
            self.log.error(f"Error building feature matrix: {e}")
            return

        n_clusters = self.config.get("model", {}).get("n_clusters", 30)
        n_clusters = max(1, min(n_clusters, len(malwares)))

        try:
            # AgglomerativeClustering has no built-in Jaccard metric, so we feed
            # it a precomputed Jaccard distance matrix.
            distances = pairwise_distances(X.astype(bool), metric="jaccard")
            model = AgglomerativeClustering(n_clusters=n_clusters, metric="precomputed", linkage="average")
            labels = model.fit_predict(distances)
        except Exception as e:
            self.log.error(f"Error during agglomerative clustering: {e}")
            return

        write_clusters(self.session, self.neo4j, X, malwares, labels, similarity_matrix, self.log)
        self.log.info(f"Agglomerative clustering assigned {len(malwares)} samples into {n_clusters} clusters.")
