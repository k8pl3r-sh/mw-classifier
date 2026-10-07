from utils.logger import Log
from utils.config import Config
from neo4j import Session

class TemplateModel:
    def __init__(self, session: Session, neo4j, redis):
        self.config = Config().get()
        self.log = Log("TEMPLATE_MODEL")
        self.neo4j = neo4j
        self.session = session
        self.redis_storage = redis


    def run(self, malware_attributes: dict, similarity_matrix=None) -> None:
        # Signature aligned with the other models: run(malware_attributes, similarity_matrix).
        # malware_attributes: {malware_name: {feature_name: set(tokens)}}
        # similarity_matrix: optional NxN numpy array to fill in place.
        pass