"""Analyzes call transcripts for voice-scam patterns: impersonation,
emotional manipulation, urgency, and requests for money/credentials."""
from mcp_server.server import dispatch
from security.input_sanitizer import sanitize_text
from agents.gemini_analyzer import GeminiAnalyzer


class CallProtectionAgent:
    name = "call_protection_agent"

    def __init__(self):
        self.gemini = GeminiAnalyzer()

    def analyze(self, transcript: str) -> dict:
        """
        Analyse a call transcript for scam risk.

        Returns a structured result including sanitizer flags, text analysis,
        and the final risk verdict.
        """
        clean = sanitize_text(transcript)

        # Try Gemini if enabled
        if self.gemini.is_enabled:
            prompt = (
                "You are an expert voice call scam protection assistant. Analyze this "
                "transcript of a voice call for potential scam indicators (impersonation, "
                "emotional manipulation, urgency, requests for sensitive details, financial payments, "
                "or requests for OTPs/verification codes which are highly malicious).\n\n"
                f"Transcript:\n{clean.clean_text}"
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
        verdict = dispatch(
            "risk_scorer",
            text_result=text_result,
            url_results=[],
            channel_hint="call",
        )
        return {
            "agent": self.name,
            "sanitizer_flags": clean.flags,
            "gemini_analyzed": False,
            "text_analysis": text_result,
            "risk": verdict,
        }

