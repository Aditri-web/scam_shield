"""Specializes in investment/financial fraud: pump-and-dump, advance-fee,
romance-scam money requests, fake crypto platforms."""
from mcp_server.server import dispatch
from security.input_sanitizer import sanitize_text
from agents.gemini_analyzer import GeminiAnalyzer

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

    def __init__(self):
        self.gemini = GeminiAnalyzer()

    def analyze(self, text: str) -> dict:
        """
        Analyse text for financial / investment fraud indicators.

        Applies both the shared scam pattern library and financial-specific
        extended patterns, then scores the combined signal.
        """
        clean = sanitize_text(text)

        # Try Gemini if enabled
        if self.gemini.is_enabled:
            prompt = (
                "You are an expert financial fraud detection assistant. Analyze the text "
                "for indications of financial scams (e.g., impersonation like Bank Support or IT Department, advance fee fraud, crypto investment scams, "
                "fake invoices, requests for gift cards or wire transfers, requests for OTP/verification codes/PIN/CVV, extreme urgency to prevent suspension/unauthorized charges, or requests to download remote access tools like AnyDesk/TeamViewer).\n\n"
                f"Text:\n{clean.clean_text}"
            )
            analysis = self.gemini.analyze(prompt)
            if analysis:
                return {
                    "agent": self.name,
                    "sanitizer_flags": clean.flags,
                    "gemini_analyzed": True,
                    "risk": {
                        "final_score": analysis.score,
                        "verdict": analysis.verdict,
                        "reasoning": analysis.reasoning,
                        "red_flags": analysis.red_flags,
                    },
                }

        # Fallback to Rule-based Analysis
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
            "gemini_analyzed": False,
            "text_analysis": text_result,
            "risk": verdict,
        }

