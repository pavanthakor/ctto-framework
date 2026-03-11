import yaml


class ConfigLoader:
    def __init__(self, path="config.yaml"):
        try:
            with open(path, "r", encoding="utf-8") as f:
                self.config = yaml.safe_load(f) or {}
        except FileNotFoundError as exc:
            raise RuntimeError(f"Config file not found: {path}") from exc
        except yaml.YAMLError as exc:
            raise RuntimeError(f"Invalid YAML in config file: {path}") from exc
