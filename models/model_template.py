from utils.logger import Log


class TemplateModel:
    def __init__(self, config: dict):
        self.config = config
        self.log = Log("TEMPLATE_MODEL", self.config)


    def run(self, malware_attribute: dict[dict]):
        # key : malware name (str)
        # value : dict avec strings, KERNEL32.dll, SHELL32.dll
        # TODO simplify the features : one per key (here IAT has one key per DLL import
        pass