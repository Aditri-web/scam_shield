"""MCP tool: analyze_text — scans free text for scam indicators using the
pattern library in resources/scam_patterns.json."""
import json
import os
import re

_HERE = os.path.dirname(__file__)
_PATTERNS_PATH = os.path.join(_HERE, "..", "resources", "scam_patterns.json")


def _load_patterns() -> dict:
    with open(_PATTERNS_PATH) as f:
        return json.load(f)


PATTERNS = _load_patterns()

_CATEGORY_WEIGHTS = {
    "urgency_phrases": 12,
    "financial_red_flags": 20,
    "impersonation_terms": 15,
    "credential_harvest_terms": 22,
    "emotional_manipulation": 18,
}


def analyze_text(text: str) -> dict:
    """Returns matched categories + matched phrases + a 0-100 raw text risk score."""
    lowered = (text or "").lower()
    findings: dict[str, list[str]] = {}

    for category, phrases in PATTERNS.items():
        hits = [p for p in phrases if p in lowered]
        if hits:
            findings[category] = hits

    score = 0
    for category, hits in findings.items():
        score += _CATEGORY_WEIGHTS.get(category, 10) * min(len(hits), 3)
    score = min(100, score)

    return {
        "matched_categories": findings,
        "category_count": len(findings),
        "raw_text_score": score,
    }
