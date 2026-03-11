import uuid

from core.config_loader import ConfigLoader
from core.database import Database
from core.logger import CTTOLogger
from core.module_loader import ModuleLoader


class Engine:
    """Central orchestrator for the CTTO framework."""

    def __init__(self, config_path="config.yaml"):
        self.config = ConfigLoader(config_path).config
        self.session_id = str(uuid.uuid4())

        fw = self.config.get("framework", {})
        db_cfg = self.config.get("database", {})
        log_cfg = self.config.get("logging", {})
        mod_cfg = self.config.get("modules", {})

        self.debug = fw.get("debug", False)
        self.services: dict[str, object] = {}

        # Logging
        self.logger = CTTOLogger(
            log_dir=log_cfg.get("log_dir", "logs"),
            level="DEBUG" if self.debug else log_cfg.get("level", "INFO"),
            max_bytes=log_cfg.get("max_bytes", 10485760),
            backup_count=log_cfg.get("backup_count", 5),
        )

        # Database
        self.db = Database(db_path=db_cfg.get("path", "data/ctto.db"))

        # Module loader
        self.loader = ModuleLoader(
            base_path=mod_cfg.get("base_path", "modules"),
            enabled_categories=mod_cfg.get("enabled_categories"),
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def start(self):
        self.logger.info(f"CTTO Engine starting  session={self.session_id}")
        self._init_database()
        self._load_modules()
        self._start_services()
        self.logger.info("CTTO Engine ready")

    def _init_database(self):
        self.db.connect()
        self.logger.info(f"Database initialised  path={self.db.db_path}")

    def _load_modules(self):
        self.loader.discover()
        count = len(self.loader.modules)
        self.logger.info(f"Loaded {count} module(s)")

    def _start_services(self):
        for name, svc in self.services.items():
            if hasattr(svc, "start"):
                self.logger.info(f"Starting service: {name}")
                svc.start()
            elif hasattr(svc, "serve_forever"):
                # External servers may already be running in their own thread.
                self.logger.debug(f"Service already active: {name}")

    # ------------------------------------------------------------------
    # Service registration
    # ------------------------------------------------------------------
    def register_service(self, name, service):
        self.services[name] = service
        self.logger.info(f"Service registered: {name}")

    # ------------------------------------------------------------------
    # Module operations
    # ------------------------------------------------------------------
    def list_modules(self):
        modules = []
        for key, mod_cls in self.loader.modules.items():
            modules.append({
                "key": key,
                "name": getattr(mod_cls, "name", key),
                "category": getattr(mod_cls, "category", "misc"),
                "description": getattr(mod_cls, "description", ""),
                "author": getattr(mod_cls, "author", "Unknown"),
            })
        return modules

    def run_module(self, module_key, **kwargs):
        mod_cls = self.loader.get_module(module_key)
        if mod_cls is None:
            self.logger.error(f"Module not found: {module_key}")
            return None

        self.logger.info(f"Running module: {module_key}")
        instance = mod_cls(engine=self)
        try:
            result = instance.run(**kwargs)
            self.logger.info(f"Module completed: {module_key}")
            return result
        except Exception as exc:
            self.logger.error(f"Module {module_key} failed: {exc}")
            raise

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------
    def get_attack_report(self):
        attacks = self.db.get_all_attacks()
        return {
            "session_id": self.session_id,
            "total_attacks": len(attacks),
            "attacks": attacks,
        }

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------
    def shutdown(self):
        self.logger.info(f"Shutting down session {self.session_id}")
        for name, svc in self.services.items():
            if hasattr(svc, "stop"):
                self.logger.info(f"Stopping service: {name}")
                svc.stop()
            elif hasattr(svc, "shutdown"):
                self.logger.info(f"Stopping service: {name}")
                svc.shutdown()
                if hasattr(svc, "server_close"):
                    svc.server_close()
        self.db.close()
        self.logger.info("Engine stopped")
