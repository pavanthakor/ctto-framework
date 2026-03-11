from core.module_loader import BaseModule


def detect_browser(user_agent):
    """Best-effort browser family detection from a User-Agent string."""
    ua = (user_agent or "").lower()

    if not ua:
        return "unknown"

    if "edg/" in ua:
        return "edge"
    if "opr/" in ua or "opera" in ua:
        return "opera"
    if "firefox/" in ua:
        return "firefox"
    # Chrome UA also contains Safari, so check Chrome first.
    if "chrome/" in ua and "chromium" not in ua and "edg/" not in ua:
        return "chrome"
    if "safari/" in ua and "chrome/" not in ua:
        return "safari"
    if "chromium" in ua:
        return "chromium"

    return "other"


def detect_automation(headers):
    """Detect automation indicators from HTTP headers.

    Returns:
        dict with keys: is_automated (bool), indicators (list[str])
    """
    hdrs = headers or {}
    normalized = {str(k).lower(): str(v).lower() for k, v in hdrs.items()}
    indicators = []

    ua = normalized.get("user-agent", "")
    sec_ch_ua = normalized.get("sec-ch-ua", "")
    accept_language = normalized.get("accept-language", "")
    webdriver = normalized.get("x-webdriver", "")

    if "python-requests" in ua:
        indicators.append("python-requests user-agent")
    if "curl/" in ua:
        indicators.append("curl user-agent")
    if "selenium" in ua or "webdriver" in ua:
        indicators.append("selenium/webdriver user-agent")
    if "headlesschrome" in ua:
        indicators.append("headless chrome user-agent")

    if "headless" in sec_ch_ua:
        indicators.append("sec-ch-ua headless hint")

    if "accept" in normalized and "accept-language" not in normalized:
        indicators.append("missing accept-language")
    if not accept_language:
        indicators.append("empty accept-language")

    if webdriver in ("1", "true", "yes"):
        indicators.append("x-webdriver header")

    # Bot traffic often sends few headers compared to normal browsers.
    if len(normalized) <= 4:
        indicators.append("very low header count")

    return {
        "is_automated": bool(indicators),
        "indicators": indicators,
    }


def detect_attack_tool(user_agent):
    """Detect common offensive tooling from a User-Agent string."""
    ua = (user_agent or "").lower()

    signatures = {
        "curl": ["curl/"],
        "python-requests": ["python-requests"],
        "hydra": ["hydra"],
        "burp suite": ["burp", "burpsuite"],
        "selenium": ["selenium", "webdriver"],
        "headless chrome": ["headlesschrome", "headless chrome"],
    }

    detected = []
    for tool, needles in signatures.items():
        if any(needle in ua for needle in needles):
            detected.append(tool)

    return detected


class RequestFingerprintModule(BaseModule):
    name = "Request Fingerprinter"
    description = "Fingerprints requests for automation and attacker tooling"
    author = "CTTO Team"
    category = "fingerprinting"

    def run(self, user_agent="", headers=None, **kwargs):
        self.log("Starting request fingerprinting")

        browser = detect_browser(user_agent)
        automation = detect_automation(headers or {})
        tools = detect_attack_tool(user_agent)

        result = {
            "browser": browser,
            "automation": automation,
            "attack_tools": tools,
            "high_risk": bool(tools) or automation["is_automated"],
        }

        self.log(f"Fingerprint result: {result}")
        self.log("Request fingerprinting complete")
        return result
