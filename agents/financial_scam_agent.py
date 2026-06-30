"""Specializes in investment/financial fraud: pump-and-dump, advance-fee,
romance-scam money requests, fake crypto platforms."""
from mcp_server.server import dispatch
from security.input_sanitizer import sanitize_text

# Domain-specific terms that aren't in the general scam_patterns.json
_EXTRA_TERMS: list[str] = [
    "guaranteed 20% monthly",
    "double your bitcoin",
    "no risk investment",
    "exclusive trading bot",
    "send the processing fee",
    "release your inheritance",
    "romance investment",
    "pig butchering",
    "liquidity mining",
    "deposit to activate",
    "trading profits locked",
    "withdrawal fee required",
]

_EXTRA_WEIGHT_PER_HIT = 15


class FinancialScamAgent:
    name = "financial_scam_agent"

    def analyze(self, text: str) -> dict:
        """
        Analyse text for financial / investment fraud indicators.

        Applies both the shared scam pattern library and financial-specific
        extended patterns, then scores the combined signal.
        """
        clean = sanitize_text(text)
        text_result = dispatch("analyze_text", text=clean.clean_text)

        lowered = clean.clean_text.lower()
        extra_hits = [t for t in _EXTRA_TERMS if t in lowered]
        if extra_hits:
            text_result.setdefault("matched_categories", {})["financial_specific"] = extra_hits
            text_result["category_count"] = len(text_result["matched_categories"])
            text_result["raw_text_score"] = min(
                100,
                text_result["raw_text_score"] + _EXTRA_WEIGHT_PER_HIT * len(extra_hits),
            )

        verdict = dispatch(
            "risk_scorer",
            text_result=text_result,
            url_results=[],
            channel_hint=None,
        )
        return {
            "agent": self.name,
            "sanitizer_flags": clean.flags,
            "text_analysis": text_result,
            "risk": verdict,
        }
