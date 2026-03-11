#!/usr/bin/env python3
"""One-time migration: normalise legacy method labels in attack_attempts.

Mapping:
    Honeypot/Login  ->  Web/Login
    API/v1/Login    ->  API/Login
    HTTP Basic      ->  BasicAuth

Run:
    python3 scripts/migrate_methods.py          (dry-run by default)
    python3 scripts/migrate_methods.py --apply  (commit changes)
"""

import argparse
import sqlite3
import sys
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "ctto.db"

MIGRATIONS = {
    "Honeypot/Login": "Web/Login",
    "API/v1/Login": "API/Login",
    "HTTP Basic": "BasicAuth",
}


def run(apply: bool) -> None:
    if not DB_PATH.exists():
        print(f"Database not found: {DB_PATH}")
        sys.exit(1)

    conn = sqlite3.connect(str(DB_PATH))
    cur = conn.cursor()

    # Show current method distribution
    cur.execute(
        "SELECT method, COUNT(*) FROM attack_attempts GROUP BY method ORDER BY method"
    )
    rows = cur.fetchall()
    print("Current method distribution:")
    for method, count in rows:
        tag = f"  -> {MIGRATIONS[method]}" if method in MIGRATIONS else ""
        print(f"  {method:20s}  {count:>5}{tag}")

    if not any(method in MIGRATIONS for method, _ in rows):
        print("\nNothing to migrate.")
        conn.close()
        return

    if not apply:
        print("\nDry-run mode. Re-run with --apply to commit changes.")
        conn.close()
        return

    total = 0
    for old, new in MIGRATIONS.items():
        cur.execute(
            "UPDATE attack_attempts SET method = ? WHERE method = ?", (new, old)
        )
        changed = cur.rowcount
        if changed:
            print(f"  Updated {changed} row(s): {old} -> {new}")
            total += changed

    conn.commit()
    conn.close()
    print(f"\nMigration complete. {total} row(s) updated.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Normalise legacy method labels")
    parser.add_argument(
        "--apply", action="store_true", help="Commit changes (default is dry-run)"
    )
    args = parser.parse_args()
    run(apply=args.apply)
