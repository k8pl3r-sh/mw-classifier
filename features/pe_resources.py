#!/usr/bin/python3

import lief
from utils.logger import Log


class PeResources:
    """Resource-directory features: resource types, available languages and the
    presence of a manifest / version info. Malware of the same family often
    ships the same resource layout."""

    def __init__(self):
        self.log = Log("PeResources")

    def __repr__(self):
        return "PeResources"

    def extract(self, filename: str) -> dict:
        tokens = set()
        try:
            binary = lief.parse(filename)
            if binary is None or not getattr(binary, "has_resources", False):
                return {}
            manager = binary.resources_manager

            for rtype in getattr(manager, "types", []) or []:
                tokens.add(f"type:{rtype}")
            for lang in getattr(manager, "langs_available", []) or []:
                tokens.add(f"lang:{lang}")
            if getattr(manager, "has_manifest", False):
                tokens.add("has:manifest")
            if getattr(manager, "has_version", False):
                tokens.add("has:version")
            if getattr(manager, "has_icons", False):
                tokens.add("has:icons")
        except Exception as e:
            self.log.debug(f"resource features not available for {filename}: {e}")
        return {'pe_resources': tokens} if tokens else {}
