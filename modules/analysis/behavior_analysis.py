from collections import defaultdict

from core.module_loader import BaseModule


class BehaviorAnalysisModule(BaseModule):
    name = "Behavior Analyzer"
    description = "Detects brute-force, credential stuffing, and manual attack behavior"
    author = "CTTO Team"
    category = "analysis"

    def detect_bruteforce(self, attempts):
        """same username many passwords -> brute force"""
        by_username = defaultdict(set)
        for a in attempts:
            username = (a.get("username") or "").strip().lower()
            password = a.get("password") or ""
            if not username:
                continue
            by_username[username].add(password)

        findings = []
        for username, passwords in by_username.items():
            if len(passwords) >= 3:
                findings.append(
                    {
                        "username": username,
                        "unique_passwords": len(passwords),
                        "pattern": "same username many passwords",
                    }
                )
        return findings

    def detect_credential_stuffing(self, attempts):
        """many usernames same password -> credential stuffing"""
        by_password = defaultdict(set)
        for a in attempts:
            username = (a.get("username") or "").strip().lower()
            password = a.get("password") or ""
            if not password:
                continue
            by_password[password].add(username)

        findings = []
        for password, usernames in by_password.items():
            if len(usernames) >= 3:
                findings.append(
                    {
                        "password": password,
                        "unique_usernames": len(usernames),
                        "pattern": "many usernames same password",
                    }
                )
        return findings

    def detect_manual_attack(self, attempts):
        """Low-volume, varied attempts that do not match bulk automated patterns."""
        if not attempts:
            return {"detected": False, "reason": "no attempts"}

        bruteforce = self.detect_bruteforce(attempts)
        stuffing = self.detect_credential_stuffing(attempts)

        # Manual probing heuristic: few attempts and no strong bulk pattern.
        unique_ips = {a.get("ip_address") for a in attempts if a.get("ip_address")}
        is_manual = len(attempts) <= 10 and not bruteforce and not stuffing and len(unique_ips) <= 2

        if is_manual:
            return {
                "detected": True,
                "reason": "low volume attempts without brute-force/stuffing pattern",
                "attempt_count": len(attempts),
                "unique_ips": len(unique_ips),
            }

        return {
            "detected": False,
            "reason": "bulk pattern detected or traffic volume too high",
            "attempt_count": len(attempts),
            "unique_ips": len(unique_ips),
        }

    def run(self, ip=None, **kwargs):
        self.log("Starting behavior analysis")

        if ip:
            attempts = self.engine.db.get_attacks_by_ip(ip)
            scope = f"ip={ip}"
        else:
            attempts = self.engine.db.get_all_attacks()
            scope = "global"

        bruteforce = self.detect_bruteforce(attempts)
        stuffing = self.detect_credential_stuffing(attempts)
        manual = self.detect_manual_attack(attempts)

        result = {
            "scope": scope,
            "total_attempts": len(attempts),
            "bruteforce_findings": bruteforce,
            "credential_stuffing_findings": stuffing,
            "manual_attack": manual,
        }

        self.log(f"Behavior analysis result: {result}")
        self.log("Behavior analysis complete")
        return result
