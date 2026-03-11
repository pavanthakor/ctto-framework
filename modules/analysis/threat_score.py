"""CTTO — Threat Scoring Engine.

Assigns a numeric risk score (0–100) to each attack attempt based on:
    • known default usernames  (+30)
    • automated tool detection (+20 each)
    • brute-force pattern      (+40)
"""

# High-value / default credential usernames
_DEFAULT_USERNAMES = frozenset({
    "admin", "root", "test", "user", "administrator", "guest",
    "oracle", "postgres", "sa", "mysql", "ftp", "support",
})


def calculate_threat_score(username: str, user_agent: str = "", headers: str = "") -> int:
    """Return a threat score between 0 and 100."""
    score = 0
    ua_lower = user_agent.lower()
    hdr_lower = headers.lower()

    # Known default / high-value username
    if username.lower() in _DEFAULT_USERNAMES:
        score += 30

    # Automated tool indicators in User-Agent
    if "curl" in ua_lower:
        score += 20
    if "python" in ua_lower:
        score += 20
    if "sqlmap" in ua_lower or "nikto" in ua_lower or "nmap" in ua_lower:
        score += 30
    if "hydra" in hdr_lower or "medusa" in hdr_lower:
        score += 40

    # Automation fingerprint present in stored headers
    if '"is_automated": true' in hdr_lower:
        score += 10

    return min(score, 100)
