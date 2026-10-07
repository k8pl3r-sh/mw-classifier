#!/usr/bin/python3

"""Ground-truth helpers: the true family of a sample is the filename prefix
before the first underscore (APT1 dataset convention)."""


def family_of(name: str) -> str:
    return name.split("_")[0]


def true_labels(names: list) -> list:
    return [family_of(n) for n in names]
