from utils.logger import Log


class TemplateModel:
    def __init__(self, config: dict):
        self.config = config
        self.log = Log("TEMPLATE_MODEL", self.config)


    def run(self):
        pass