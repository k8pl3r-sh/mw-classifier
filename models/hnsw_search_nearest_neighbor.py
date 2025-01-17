import numpy as np

from engine.redis_storage import RedisStorage
from utils.logger import Log
import hnswlib
from utils.config import Config
from neo4j import Session

class HnswSearchNearestNeighbor:
    def __init__(self, session: Session, neo4j, redis):
        self.config = Config().get()
        self.redis_storage = RedisStorage()
        self.dim = self.config['hnsw']['dimension']  # Dimension of the MinHash signatures
        self.max_elements = self.config['hnsw']['max_elements']  # Maximum number of elements in HNSW index
        self.log = Log("HnswSearchNearestNeighbor")
        self.id_map = {}  # Map for storing the mapping of malware IDs to index

        self.index = hnswlib.Index(space='l2', dim=self.dim)  # Initialize HNSW index with L2 distance
        self.index.init_index(max_elements=self.max_elements, ef_construction=200, M=16)  # Adjust parameters as needed
        self.neo4j = neo4j
        self.session = session
        self.redis_storage = redis

    def add_signature(self, malware_id, minhash_signature) -> None:
        # Use the current size of the index as the new index for the incoming ID
        current_index = self.index.get_current_count()

        # Ensure hashvalues are float32 and reshape correctly
        hash_values = minhash_signature.hashvalues.astype(np.float32).reshape(1, -1)

        self.index.add_items(hash_values, ids=np.array([current_index], dtype=np.int32))
        # Map the string malware_id to its index
        self.id_map[malware_id] = current_index

    def query(self, query_hashvalues: str, k: int = 5) -> tuple[list, list]:
        # Query the HNSW index
        labels, distances = self.index.knn_query(query_hashvalues, k=k)
        # Convert labels from index back to original malware_id
        original_ids = [list(self.id_map.keys())[label] for label in labels[0]]
        return original_ids, distances[0]

    def run(self) -> None:
        ...