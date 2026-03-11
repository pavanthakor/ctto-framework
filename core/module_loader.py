import importlib.util
import os
from abc import ABC, abstractmethod


class BaseModule(ABC):
    """Base class every CTTO module must inherit from."""

    name: str = "Unnamed Module"
    description: str = ""
    author: str = "Unknown"
    category: str = "misc"

    def __init__(self, engine):
        self.engine = engine

    @abstractmethod
    def run(self, **kwargs):
        """Execute the module's primary logic."""

    def log(self, msg):
        self.engine.logger.info(f"[{self.name}] {msg}")

    def log_attack(self, ip, username, password, method, user_agent="", headers=""):
        self.engine.logger.log_attack(ip, username, password, method, user_agent)
        self.engine.db.log_attack(ip, username, password, method, user_agent, headers)


class ModuleLoader:
    """Discovers and loads CTTO modules from the modules/ directory tree."""

    def __init__(self, base_path="modules", enabled_categories=None):
        self.base_path = base_path
        self.enabled_categories = enabled_categories
        self.modules: dict[str, type] = {}
        self.load_errors: list[dict[str, str]] = []

    def discover(self):
        self.modules.clear()
        self.load_errors.clear()
        if not os.path.isdir(self.base_path):
            return

        for category in sorted(os.listdir(self.base_path)):
            cat_dir = os.path.join(self.base_path, category)
            if not os.path.isdir(cat_dir):
                continue
            if self.enabled_categories and category not in self.enabled_categories:
                continue
            for filename in sorted(os.listdir(cat_dir)):
                if filename.startswith("_") or not filename.endswith(".py"):
                    continue
                filepath = os.path.join(cat_dir, filename)
                self._load_module_file(filepath, category)

    def _load_module_file(self, filepath, category):
        module_name = os.path.splitext(os.path.basename(filepath))[0]
        fq_name = f"modules.{category}.{module_name}"
        spec = importlib.util.spec_from_file_location(fq_name, filepath)
        if spec is None or spec.loader is None:
            return
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
        except Exception as exc:
            self.load_errors.append(
                {
                    "file": filepath,
                    "error": str(exc),
                }
            )
            raise RuntimeError(f"Module load failed: {filepath}") from exc

        for attr_name in dir(mod):
            attr = getattr(mod, attr_name)
            if (
                isinstance(attr, type)
                and issubclass(attr, BaseModule)
                and attr is not BaseModule
            ):
                key = f"{category}/{module_name}"
                attr.category = category
                self.modules[key] = attr

    def get_module(self, key):
        return self.modules.get(key)

    def list_modules(self):
        return list(self.modules.keys())
