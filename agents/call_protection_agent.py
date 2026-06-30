"""Analyzes call transcripts for voice-scam patterns: impersonation,
emotional manipulation, urgency, and requests for money/credentials."""
from mcp_server.server import dispatch
from security.input_sanitizer import sanitize_text


class CallProtectionAgent:
    name = "call_protection_agent"

    def analyze(self, transcript: str) -> dict:
        """
        Analyse a call transcript for scam risk.

        Returns a structured result including sanitizer flags, text analysis,
        and the final risk verdict.
        """
        clean = sanitize_text(transcript)
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
            "text_analysis": text_result,
            "risk": verdict,
        }
