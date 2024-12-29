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


    def run(self, malware_attribute: dict[dict]):
        # key : malware name (str)
        # value : dict avec strings, KERNEL32.dll, SHELL32.dll
        # TODO simplify the features : one per key (here IAT has one key per DLL import
        pass