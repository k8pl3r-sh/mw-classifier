
import numpy as np
from neo4j import Session

from utils.logger import Log
from utils.config import Config
from datasketch import MinHashLSH, MinHash
from engine.minhashcustom import MinHashCustom


class LSH_Model:
    def __init__(self, session: Session, neo4j, redis):
        self.config = Config().get()
        self.log = Log("LSH_Model")
        self.minhash_custom = MinHashCustom()
        self.neo4j = neo4j
        self.session = session
        self.redis_storage = redis

    def generate_minhash_signatures(self, lsh: MinHashLSH):
        minhashes = {}
        for malware, attributes in self.malware_attributes.items():
            minhash = MinHash(num_perm=128)

            # Combine all features' MinHash signatures for the malware
            for feature_name, feature_set in attributes.items():
                for idx, is_true in enumerate(feature_set):
                    if is_true:
                        minhash.update(str(idx).encode('utf8'))

            # Store the MinHash signature and insert it into the LSH index
            minhashes[malware] = minhash
            lsh.insert(malware, minhash)

            # WORK: Store the MinHash signature in Redis
            if self.config["database"]["redis"] == True:
                try:
                    self.redis_storage.store_minhash_signature(malware, minhash)
                except Exception as e:
                    self.log.error(f"Error {e} : Probably Redis docker not started via docker-compose up -d")

            # WORK: Add the MinHash signature to the HNSW index
            # self.hnsw_search.add_signature(malware, minhash)

        return minhashes

    def create_relationships(self, lsh: MinHashLSH, minhashes: dict):
        for malware1, minhash1 in minhashes.items():
            similar_malwares = lsh.query(minhash1)

            for malware2 in similar_malwares:
                if malware1 != malware2:
                    # Ensure only one relationship is created by always using the lexicographically smaller malware first
                    if malware1 < malware2:
                        # Compute the approximate Jaccard similarity if needed
                        jaccard_indexes = []

                        union_keys = set(self.malware_attributes[malware1].keys()).union(
                            set(self.malware_attributes[
                                    malware2].keys()))  # compilation of all features names of both binaries

                        for feature_name in union_keys:
                            # TODO : can be syntax optimized with if/else ? Warn of Key error if not found
                            m1_f = self.malware_attributes.get(malware1, {}).get(feature_name, [])
                            m2_f = self.malware_attributes.get(malware2, {}).get(feature_name, [])

                            if len(m1_f) == 0:  # features need to have the same length to be compared
                                m1_f = [None] * len(m2_f)
                            elif len(m2_f) == 0:
                                m2_f = [None] * len(m1_f)

                            # TODO : have to replace the following line by minhash1.jaccard(minhash2), here it is 2 hashed lists
                            feature_similarity_index = self.minhash_custom.compute_minhash_similarity(m1_f, m2_f)
                            jaccard_indexes.append(feature_similarity_index)

                        jaccard_index = np.mean(
                            jaccard_indexes)  # mean of all features to have a global similarity index

                        if jaccard_index > self.config["model"]["threshold"]:
                            self.session.execute_write(self.neo4j.create_relationship, malware1, malware2, jaccard_index)

                        # Update the similarity matrix
                        # TODO solve attributeError : dict object has no attribute index
                        #index_1 = self.malware_attributes.index(malware1)
                        #index_2 = self.malware_attributes.index(malware2)
                        #self.similarity_matrix[index_1, index_2] = jaccard_index
                        #self.similarity_matrix[index_2, index_1] = jaccard_index

    def run(self, malware_attributes: dict[dict], similarity_matrix) -> None:
        self.malware_attributes = malware_attributes
        self.similarity_matrix = similarity_matrix

        # key : malware name (str)
        # value : dict avec strings, KERNEL32.dll, SHELL32.dll
        # TODO simplify the features : one per key (here IAT has one key per DLL import
        # def search_similarities_lsh(self, session):

        # Initialize LSH
        # Doc : http://ekzhu.com/datasketch/lsh.html
        try:
            lsh = MinHashLSH(threshold=self.config["model"]["threshold"], num_perm=128)
        except ValueError:
            self.log.error(" The number of bands are too small (b < 2)")
            return


        # Generate MinHash signatures using the datasketch MinHash object and insert them into LSH
        minhashes = self.generate_minhash_signatures(lsh)

        # Now query the LSH for similar malwares and create relationships
        self.create_relationships(lsh, minhashes)