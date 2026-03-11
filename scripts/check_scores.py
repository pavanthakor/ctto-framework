"""Quick helper to print latest attacks with threat scores."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.database import Database

db = Database("data/ctto.db")
db.connect()
attacks = db.get_recent_attacks(5)
for a in attacks:
    uid = a["id"]
    user = a["username"]
    method = a["method"]
    score = a["threat_score"]
    ua = (a.get("user_agent") or "")[:30]
    print(f"ID={uid}  user={user}  method={method}  score={score}  ua={ua}")
db.close()
