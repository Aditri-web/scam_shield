"""Analyzes email content + embedded links for phishing indicators."""
from mcp_server.server import dispatch
from mcp_server.tools.check_url import extract_urls
from security.input_sanitizer import sanitize_text
from agents.gemini_analyzer import GeminiAnalyzer


class PhishingEmailAgent:
    name = "phishing_email_agent"

    def __init__(self):
        self.gemini = GeminiAnalyzer()

    def analyze(self, email_text: str, sender: str | None = None) -> dict:
        """
        Analyse an email for phishing risk.

        Args:
            email_text: Raw email body (HTML or plain text).
            sender: The From address (e.g. 'support@amaz0n-secure-login.xyz').

        Returns a structured result including URL analysis, sender domain
        check, text analysis, and the final risk verdict.
        """
        clean = sanitize_text(email_text)

        # 1. Gather structural/reputation checks to supply as context
        urls = extract_urls(clean.clean_text)
        url_results = [dispatch("check_url", url=u) for u in urls]

        sender_flag = None
        sender_check_details = None
        if sender and "@" in sender:
            domain = sender.split("@")[-1].lower()
            check = dispatch("check_url", url=domain)
            sender_check_details = check
            if check["is_typosquat_suspect"]:
                sender_flag = f"sender_domain_typosquat:{check['closest_known_domain']}"

        # 2. Try Gemini if enabled
        if self.gemini.is_enabled:
            url_context_lines = []
            for r in url_results:
                flags_str = ", ".join(r["flags"]) if r["flags"] else "none"
                url_context_lines.append(
                    f"- URL: {r['url']} (Risk Score: {r['url_risk_score']}, Flags: {flags_str}, Closest Known: {r['closest_known_domain']})"
                )
            url_context = "\n".join(url_context_lines) if url_context_lines else "None detected."

            sender_context = f"Sender: {sender}"
            if sender_check_details:
                sender_flags = ", ".join(sender_check_details["flags"]) if sender_check_details["flags"] else "none"
                sender_context += f" (Domain check flags: {sender_flags}, Closest Known: {sender_check_details['closest_known_domain']})"

            prompt = (
                "You are an expert phishing email detection assistant. Analyze the email body, sender, "
                "and embedded links for phishing indicators (e.g., impersonation, lookalike domains, credential harvesting, "
                "urgency, suspicious links).\n\n"
                f"Context:\n"
                f"  {sender_context}\n"
                f"  Embedded Link Analysis:\n{url_context}\n\n"
                f"Email Body:\n{clean.clean_text}"
            )
            analysis = self.gemini.analyze(prompt)
            if analysis:
                return {
                    "agent": self.name,
                    "sanitizer_flags": clean.flags,
                    "gemini_analyzed": True,
                    "url_analysis": url_results,
                    "sender_flag": sender_flag,
                    "risk": {
                        "final_score": analysis.score,
                        "verdict": analysis.verdict,
                        "reasoning": analysis.reasoning,
                        "red_flags": analysis.red_flags,
                    },
                }

        # 3. Fallback to Rule-based Analysis
        text_result = dispatch("analyze_text", text=clean.clean_text)
        verdict = dispatch(
            "risk_scorer",
            text_result=text_result,
            url_results=url_results,
            channel_hint="email",
        )
        return {
            "agent": self.name,
            "sanitizer_flags": clean.flags,
            "gemini_analyzed": False,
            "text_analysis": text_result,
            "url_analysis": url_results,
            "sender_flag": sender_flag,
            "risk": verdict,
        }

