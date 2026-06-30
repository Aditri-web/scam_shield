"""MCP tool: check_url — flags suspicious URLs via lookalike-domain and
typosquat heuristics against the trusted domain list."""
import json
import os
import re
from urllib.parse import urlparse

_HERE = os.path.dirname(__file__)
_DOMAINS_PATH = os.path.join(_HERE, "..", "resources", "legitimate_domains.json")


def _load_domains() -> dict:
    with open(_DOMAINS_PATH) as f:
        return json.load(f)


DOMAIN_DATA = _load_domains()


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    dp = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        prev, dp[0] = dp[0], i
        for j, cb in enumerate(b, 1):
            cur = dp[j]
            dp[j] = min(dp[j] + 1, dp[j - 1] + 1, prev + (ca != cb))
            prev = cur
    return dp[-1]


def extract_urls(text: str) -> list[str]:
    """Extract all http(s) URLs from a block of text."""
    return re.findall(r"https?://[^\s\])\>\"\']+", text or "")


def check_url(url: str) -> dict:
    """
    Analyse a single URL for risk signals:
      - Suspicious TLD (e.g. .xyz, .top)
      - Missing HTTPS
      - Typosquatting / lookalike of a known trusted domain

    Returns a dict with flags and a 0-100 url_risk_score.
    """
    parsed = urlparse(url if "://" in url else "http://" + url)
    host = parsed.netloc.lower().split(":")[0]
    flags: list[str] = []

    # Suspicious TLD check
    if any(host.endswith(tld) for tld in DOMAIN_DATA["common_lookalike_tlds"]):
        flags.append("suspicious_tld")

    # HTTPS check
    if not url.startswith("https://"):
        flags.append("no_https")

    # Normalize common leetspeak (0→o, 1→l/i, 3→e) before comparing
    normalized_host = host.translate(str.maketrans("013", "oie"))
    host_brand = normalized_host.split(".")[0].split("-")[0]

    closest, dist = None, 99
    for trusted in DOMAIN_DATA["trusted_domains"]:
        trusted_brand = trusted.split(".")[0]
        d = min(_levenshtein(host, trusted), _levenshtein(host_brand, trusted_brand))
        if d < dist:
            closest, dist = trusted, d

    is_typosquat = bool(closest) and dist <= 2 and host != closest
    if is_typosquat:
        flags.append(f"typosquat_of:{closest}")

    is_trusted = host in DOMAIN_DATA["trusted_domains"]

    risk = 0
    if is_typosquat:
        risk += 60
    if "suspicious_tld" in flags:
        risk += 20
    if "no_https" in flags:
        risk += 10
    if is_trusted:
        risk = 0

    return {
        "url": url,
        "host": host,
        "is_trusted": is_trusted,
        "is_typosquat_suspect": is_typosquat,
        "closest_known_domain": closest,
        "edit_distance": dist,
        "flags": flags,
        "url_risk_score": min(100, risk),
    }
