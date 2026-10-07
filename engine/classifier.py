#!/usr/bin/python3

import numpy as np
import hnswlib
from datasketch import MinHash

from utils.logger import Log
from utils.config import Config
from utils.tools import filename_from_path, is_supported_binary
from features.features_extractor import FeaturesExtractor


class Classifier:
    """
    Attribute a *single* binary to the nearest known malware family.

    The corpus and the query share the same representation as LSH_Model: one
    datasketch MinHash per sample over its feature tokens (prefixed with the
    feature name). Similarity is the exact MinHash Jaccard.

    Search strategy:
      - small corpus (<= BRUTE_FORCE_MAX): exact brute-force Jaccard (correct);
      - large corpus: HNSW approximate recall over the MinHash signatures,
        then exact Jaccard re-ranking of the recalled candidates.
    """

    NUM_PERM = 128
    BRUTE_FORCE_MAX = 5000

    def __init__(self, malware_attributes: dict):
        self.config = Config().get()
        self.log = Log("Classifier")
        self.malware_attributes = malware_attributes
        self.names = list(malware_attributes.keys())
        self.minhashes = {name: self._build_minhash(attrs) for name, attrs in malware_attributes.items()}
        self.index = None
        if len(self.names) > self.BRUTE_FORCE_MAX:
            self._build_index()

    @staticmethod
    def family_of(name: str) -> str:
        return name.split("_")[0]

    def _build_minhash(self, attributes: dict) -> MinHash:
        mh = MinHash(num_perm=self.NUM_PERM)
        for feature_name, tokens in attributes.items():
            for token in tokens:
                mh.update(f"{feature_name}:{token}".encode("utf8"))
        return mh

    def _build_index(self) -> None:
        n = len(self.names)
        try:
            index = hnswlib.Index(space='l2', dim=self.NUM_PERM)
            index.init_index(max_elements=n, ef_construction=200, M=16)
            vectors = np.array([self.minhashes[name].hashvalues for name in self.names], dtype=np.float32)
            index.add_items(vectors, np.arange(n))
            index.set_ef(max(64, self.NUM_PERM))
            self.index = index
            self.log.info(f"HNSW index built over {n} samples.")
        except Exception as e:
            self.log.warn(f"HNSW index unavailable ({e}); using brute-force search.")
            self.index = None

    def _candidates(self, query_mh: MinHash, k: int) -> list:
        # Exact over the whole corpus unless it is large enough to need ANN.
        if self.index is None:
            return list(self.names)
        n = len(self.names)
        n_query = min(n, max(k * 10, 100))  # over-fetch, then re-rank exactly
        labels, _ = self.index.knn_query(np.array([query_mh.hashvalues], dtype=np.float32), k=n_query)
        return [self.names[i] for i in labels[0]]

    def classify(self, query_attributes: dict, k: int = 5) -> dict:
        query_mh = self._build_minhash(query_attributes)
        candidates = self._candidates(query_mh, k)

        scored = sorted(
            ((name, query_mh.jaccard(self.minhashes[name])) for name in candidates),
            key=lambda pair: pair[1], reverse=True
        )[:k]

        # Family vote weighted by similarity
        votes = {}
        for name, score in scored:
            fam = self.family_of(name)
            votes[fam] = votes.get(fam, 0.0) + score

        total = sum(votes.values())
        if total > 0:
            predicted_family, fam_score = max(votes.items(), key=lambda pair: pair[1])
            confidence = fam_score / total
        else:
            predicted_family, confidence = None, 0.0

        return {
            "predicted_family": predicted_family,
            "confidence": confidence,
            "best_score": scored[0][1] if scored else 0.0,
            "neighbors": [
                {"name": name, "family": self.family_of(name), "score": score}
                for name, score in scored
            ],
        }

    def classify_file(self, filepath: str, k: int = 5) -> dict:
        if not is_supported_binary(filepath):
            raise ValueError(f"{filepath} is not a supported binary (PE/ELF/Mach-O)")
        extractor = FeaturesExtractor()
        attributes = extractor.extract_features(filepath)
        result = self.classify(attributes, k=k)
        result["query"] = filename_from_path(filepath)
        return result
