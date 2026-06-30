"""MCP tool: risk_scorer — combines signals from analyze_text and
check_url (and optional channel metadata) into one final verdict."""

THRESHOLDS = {"low": 30, "medium": 60, "high": 80}

_CHANNEL_WEIGHTS: dict[str | None, int] = {
    "call": 5,
    "sms": 8,
    "email": 0,
    "social_media": 6,
    None: 0,
}


def risk_scorer(
    text_result: dict | None,
    url_results: list[dict],
    channel_hint: str | None = None,
) -> dict:
    """
    Combine text + URL signals into a single 0-100 score and verdict.

    Weights:
      55% text score, 35% URL score, up to +8 channel weight.
    """
    text_score = (text_result or {}).get("raw_text_score", 0)
    channel_weight = _CHANNEL_WEIGHTS.get(channel_hint, 0)
    
    if url_results:
        url_score = max((r.get("url_risk_score", 0) for r in url_results), default=0)
        combined = round(0.55 * text_score + 0.35 * url_score + channel_weight)
    else:
        url_score = 0
        # When there are no URLs, we rely mostly on the text score
        combined = round(0.9 * text_score + channel_weight)
        
    combined = min(100, combined)

    if combined >= THRESHOLDS["high"]:
        verdict = "HIGH_RISK_SCAM"
    elif combined >= THRESHOLDS["medium"]:
        verdict = "LIKELY_SCAM"
    elif combined >= THRESHOLDS["low"]:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LIKELY_SAFE"

    return {
        "final_score": combined,
        "verdict": verdict,
        "components": {
            "text_score": text_score,
            "url_score": url_score,
            "channel_weight": channel_weight,
        },
    }
