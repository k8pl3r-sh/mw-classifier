
from neo4j import Session

from utils.logger import Log
from utils.config import Config
from datasketch import MinHashLSH, MinHash


class LSH_Model:
    def __init__(self, session: Session, neo4j, redis):
        self.config = Config().get()
        self.log = Log("LSH_Model")
        self.neo4j = neo4j
        self.session = session
        self.redis_storage = redis

    def generate_minhash_signatures(self, lsh: MinHashLSH) -> dict:
        """
        Build one MinHash signature per malware over its raw feature tokens
        and insert it into the LSH index.

        Tokens are prefixed with their feature name (e.g. "strings:foo",
        "KERNEL32.dll:CreateFileA") so that a string and an imported function
        with the same text are not conflated.
        """
        minhashes = {}
        for malware, attributes in self.malware_attributes.items():
            minhash = MinHash(num_perm=128)

            for feature_name, tokens in attributes.items():
                for token in tokens:
                    minhash.update(f"{feature_name}:{token}".encode("utf8"))

            minhashes[malware] = minhash
            lsh.insert(malware, minhash)

            if self.config["database"]["redis"]:
                try:
                    self.redis_storage.store_minhash_signature(malware, minhash)
                except Exception as e:
                    self.log.error(f"Error {e} : Probably Redis docker not started via docker-compose up -d")

        return minhashes

    def create_relationships(self, lsh: MinHashLSH, minhashes: dict) -> None:
        for malware1, minhash1 in minhashes.items():
            for malware2 in lsh.query(minhash1):
                # Each unordered pair is handled once (malware1 < malware2),
                # which also skips the self-match.
                if malware1 < malware2:
                    jaccard_index = minhash1.jaccard(minhashes[malware2])

                    # Record the raw similarity in the matrix (symmetric),
                    # regardless of the threshold.
                    index_1 = self.index_of[malware1]
                    index_2 = self.index_of[malware2]
                    self.similarity_matrix[index_1, index_2] = jaccard_index
                    self.similarity_matrix[index_2, index_1] = jaccard_index

                    if jaccard_index > self.config["model"]["threshold"]:
                        self.session.execute_write(self.neo4j.create_relationship, malware1, malware2, jaccard_index)

    def run(self, malware_attributes: dict[dict], similarity_matrix) -> None:
        self.malware_attributes = malware_attributes
        self.similarity_matrix = similarity_matrix
        # Map each malware name to its row/column index in the similarity matrix.
        # The order matches malware_attributes.keys(), i.e. the order used by the
        # engine when it builds the matrix and the heatmap labels.
        self.index_of = {name: i for i, name in enumerate(malware_attributes.keys())}

        # Initialize LSH
        # Doc : http://ekzhu.com/datasketch/lsh.html
        try:
            lsh = MinHashLSH(threshold=self.config["model"]["threshold"], num_perm=128)
        except ValueError:
            self.log.error(" The number of bands are too small (b < 2)")
            return

        # Build the MinHash signatures and insert them into LSH
        minhashes = self.generate_minhash_signatures(lsh)

        # Query the LSH for similar malwares and create relationships
        self.create_relationships(lsh, minhashes)
