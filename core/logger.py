import logging
import os
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler


class CTTOLogger:
    def __init__(self, log_dir="logs", level="INFO", max_bytes=10485760, backup_count=5):
        os.makedirs(log_dir, exist_ok=True)
        self.log_dir = log_dir
        self.level = getattr(logging, level.upper(), logging.INFO)

        self.logger = self._build_logger(
            "ctto",
            os.path.join(log_dir, "ctto.log"),
            max_bytes,
            backup_count,
        )

    def _build_logger(self, name, filepath, max_bytes, backup_count):
        logger = logging.getLogger(name)
        logger.setLevel(self.level)

        if logger.handlers:
            return logger

        fmt = logging.Formatter(
            "[%(asctime)s] %(levelname)-8s %(name)s :: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        fh = RotatingFileHandler(filepath, maxBytes=max_bytes, backupCount=backup_count)
        fh.setLevel(self.level)
        fh.setFormatter(fmt)
        logger.addHandler(fh)

        ch = logging.StreamHandler()
        ch.setLevel(self.level)
        ch.setFormatter(fmt)
        logger.addHandler(ch)

        return logger

    # --- standard log levels ---
    def info(self, msg):
        self.logger.info(msg)

    def debug(self, msg):
        self.logger.debug(msg)

    def warning(self, msg):
        self.logger.warning(msg)

    def error(self, msg):
        self.logger.error(msg)

    def critical(self, msg):
        self.logger.critical(msg)

    # --- attack logging ---
    def log_attack(self, ip, username, password, method, user_agent=""):
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        entry = (
            f"ATTACK  ip={ip}  user={username}  method={method}  "
            f"user_agent={user_agent}  ts={ts}"
        )
        self.logger.warning(entry)
