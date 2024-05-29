def jaccard(set1: set, set2: set, simplify=True) -> float:
    """
    Compute the Jaccard distance between two sets [0,1]
    """
    intersect = set1.intersection(set2)
    intersect_length = float(len(intersect))
    union = set1.union(set2)
    union_length = float(len(union))
    if simplify:
        return round(intersect_length / union_length, 3)
    return intersect_length / union_length
