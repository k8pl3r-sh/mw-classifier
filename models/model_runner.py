import os
import importlib
from utils.logger import Log

current_file_path = os.path.abspath(__file__)  # Absolute path of the current file
MODELS_FOLDER = os.path.abspath(os.path.dirname(current_file_path))

class ModelRunner:
    def __init__(self, config: dict, model_name: str):
        self.config = config
        self.log = Log("FeaturesExtractor", config)
        self.model_name = model_name
        self.models = self._load_models()

    def run_model(self):
        ...

    def _load_models(self) -> list[object]:
        model_files = [file for file in os.listdir(MODELS_FOLDER) if file.endswith(".py")]
        model_files.remove(os.path.basename(__file__))  # remove current file
        # TODO : way to select features to load by specifying them in the config file

        models = {}
        for file in model_files:

            file_path = os.path.join(MODELS_FOLDER, file)
            file = file.replace(".py", "")
            model_name = ''.join(word.title() for word in file.split('_'))  # snake_deluxe -> SnakeDeluxe

            spec = importlib.util.spec_from_file_location(model_name, file_path)
            model = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(model)

            model_class = getattr(model, model_name)
            if model_class:
                models[model_name] = model_class(self.config)
        self.log.info(f"Loaded {len(models)} features : {models}")
        return models