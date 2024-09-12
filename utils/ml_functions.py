#!/usr/bin/env python3
#from scipy.spatial.distance import jaccard


def jaccard(set1: set, set2: set, simplify=True) -> float:
    """
    #Compute the Jaccard index between two sets. The Jaccard index is a measure of similarity
    #between two sets and is defined as the size of the intersection divided by the size of the union of the sets.

    #Args:
    #    set1 (set): The first set.
    #    set2 (set): The second set.
    #    simplify (bool, optional): If True, round the result to three decimal places. Default is True.

    #Returns:
    #    float: The Jaccard index, a value between 0 and 1, where 0 means no similarity and 1 means identical sets.

    Examples:
        >>> jaccard({'a', 'b', 'c'}, {'b', 'c', 'd'})
        0.5
        >>> jaccard({'a', 'b', 'c'}, {'d', 'e', 'f'})
        0.0
        >>> jaccard({'a', 'b', 'c'}, {'a', 'b', 'c'})
        1.0
        >>> jaccard({'a', 'b', 'c'}, {'b', 'c', 'd'}, simplify=False)
        0.5
        >>> jaccard({'a', 'b', 'c'}, {'a', 'b', 'c', 'd'}, simplify=False)
        0.75
    # Fin docstring
    """
    
    intersect = set1.intersection(set2)
    intersect_length = float(len(intersect))
    union = set1.union(set2)
    union_length = float(len(union))
    if simplify:
        return round(intersect_length / union_length, 3)
    return intersect_length / union_length
