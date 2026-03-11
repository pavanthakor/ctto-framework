"""CTTO — Attack Report Exporter.

Exports attack telemetry from the database to CSV or JSON.

Usage:
    python3 ctto.py export                  # CSV (default)
    python3 ctto.py export --format json    # JSON
    python3 ctto.py export -o report.csv    # custom filename
"""

import csv
import json
import os

from core.database import Database

DB_PATH = "data/ctto.db"


def export_csv(output_path: str = "attack_report.csv") -> str:
    db = Database(DB_PATH)
    db.connect()
    attacks = db.get_all_attacks()
    db.close()

    with open(output_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "id", "timestamp", "ip_address", "username", "password",
            "method", "threat_score", "user_agent",
        ])
        for a in attacks:
            writer.writerow([
                a["id"],
                a["timestamp"],
                a["ip_address"],
                a["username"],
                a.get("password", ""),
                a["method"],
                a.get("threat_score", 0),
                a.get("user_agent", ""),
            ])

    return os.path.abspath(output_path)


def export_json(output_path: str = "attack_report.json") -> str:
    db = Database(DB_PATH)
    db.connect()
    attacks = db.get_all_attacks()
    db.close()

    with open(output_path, "w") as f:
        json.dump(attacks, f, indent=2, default=str)

    return os.path.abspath(output_path)
