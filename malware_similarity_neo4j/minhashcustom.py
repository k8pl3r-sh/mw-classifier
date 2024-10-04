import mmh3
import numpy as np

"""
This optimization needs to be really well explained because it is a bit complex, but very efficient.
It reduce exec time more than half on APT1 family samples."""


class MinHashCustom:
    def __init__(self):
        pass

    def generate_minhash_signature(self, array: np.array) -> list:
        """
        Generate MinHash signature for a given boolean array.

        Parameters:
        - array: a boolean array where True represents the presence of a feature.

        Returns:
        - MinHash signature (list of minimum hashes).
        """
        # List to store the minhashes
        minhashes = [float('inf')] * 128

        # Iterate over the indices of True values in the boolean array
        for idx, is_true in enumerate(array):
            if is_true:
                # Generate a hash for each of the 'num_hashes' different seeds
                for seed in range(128):
                    hash_value = mmh3.hash(str(idx), seed)
                    # Update the minimum hash value for this seed
                    if hash_value < minhashes[seed]:
                        minhashes[seed] = hash_value

        return minhashes

    @staticmethod
    def compute_minhash_similarity(signature1: list, signature2: list) -> float:
        """
        Compute the similarity between two MinHash signatures.

        Parameters:
        - signature1: MinHash signature from array 1.
        - signature2: MinHash signature from array 2.

        Returns:
        - Approximate Jaccard similarity.
        """
        assert len(signature1) == len(signature2), "Signatures must be of the same length"

        # Count the number of positions where the two signatures match
        num_equal = sum(1 for h1, h2 in zip(signature1, signature2) if h1 == h2)

        # Return the fraction of matching hashes
        return num_equal / len(signature1)
