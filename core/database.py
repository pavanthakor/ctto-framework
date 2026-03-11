import os
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Index, Integer, String, Text, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    pass


class AttackAttempt(Base):
    __tablename__ = "attack_attempts"
    __table_args__ = (
        Index("ix_attack_attempts_timestamp", "timestamp"),
        Index("ix_attack_attempts_ip_address", "ip_address"),
        Index("ix_attack_attempts_username", "username"),
        Index("ix_attack_attempts_method", "method"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    ip_address = Column(String(45), nullable=False)
    username = Column(String(256), nullable=False)
    password = Column(String(256), nullable=False)
    method = Column(String(32), nullable=False)
    threat_score = Column(Integer, default=0)
    user_agent = Column(Text, default="")
    headers = Column(Text, default="")


class Database:
    def __init__(self, db_path="data/ctto.db"):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self.engine = None
        self._session_factory = None

    def connect(self):
        self.engine = create_engine(
            f"sqlite:///{self.db_path}",
            echo=False,
            connect_args={"check_same_thread": False, "timeout": 30},
        )

        @event.listens_for(self.engine, "connect")
        def _set_sqlite_pragmas(dbapi_connection, _connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA busy_timeout=30000")
            cursor.close()

        Base.metadata.create_all(self.engine)
        self._session_factory = sessionmaker(bind=self.engine)

    def get_session(self) -> Session:
        return self._session_factory()

    def log_attack(self, ip, username, password, method, user_agent="", headers="", threat_score=None):
        if threat_score is None:
            try:
                from modules.analysis.threat_score import calculate_threat_score
                threat_score = calculate_threat_score(username, user_agent, headers)
            except Exception:
                threat_score = 0
        with self.get_session() as session:
            attempt = AttackAttempt(
                ip_address=ip,
                username=username,
                password=password,
                method=method,
                threat_score=threat_score,
                user_agent=user_agent,
                headers=headers,
            )
            session.add(attempt)
            session.commit()
            return attempt.id

    def save_attempt(self, ip, username, password, user_agent="", headers=""):
        """Deprecated compatibility alias.

        New code should call `log_attack(..., method=<explicit>)` directly.
        """
        return self.log_attack(
            ip=ip,
            username=username,
            password=password,
            method="Web/Login",
            user_agent=user_agent,
            headers=headers,
        )

    def get_all_attacks(self):
        with self.get_session() as session:
            rows = session.query(AttackAttempt).order_by(AttackAttempt.timestamp).all()
            return [
                {
                    "id": r.id,
                    "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                    "ip_address": r.ip_address,
                    "username": r.username,
                    "password": r.password,
                    "method": r.method,
                    "threat_score": r.threat_score or 0,
                    "user_agent": r.user_agent,
                    "headers": r.headers,
                }
                for r in rows
            ]

    def get_attacks_by_ip(self, ip):
        with self.get_session() as session:
            rows = (
                session.query(AttackAttempt)
                .filter(AttackAttempt.ip_address == ip)
                .order_by(AttackAttempt.timestamp)
                .all()
            )
            return [
                {
                    "id": r.id,
                    "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                    "ip_address": r.ip_address,
                    "username": r.username,
                    "password": r.password,
                    "method": r.method,
                    "user_agent": r.user_agent,
                    "headers": r.headers,
                }
                for r in rows
            ]

    def get_recent_attacks(self, limit=20):
        with self.get_session() as session:
            rows = (
                session.query(AttackAttempt)
                .order_by(AttackAttempt.timestamp.desc())
                .limit(limit)
                .all()
            )
            return [
                {
                    "id": r.id,
                    "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                    "ip_address": r.ip_address,
                    "username": r.username,
                    "password": r.password,
                    "method": r.method,
                    "threat_score": r.threat_score or 0,
                    "user_agent": r.user_agent,
                    "headers": r.headers,
                }
                for r in rows
            ]

    def get_attack_count(self):
        with self.get_session() as session:
            return session.query(AttackAttempt).count()

    def close(self):
        if self.engine:
            self.engine.dispose()
            self.engine = None
