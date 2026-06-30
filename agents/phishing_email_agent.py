"""Analyzes email content + embedded links for phishing indicators."""
from mcp_server.server import dispatch
from mcp_server.tools.check_url import extract_urls
from security.input_sanitizer import sanitize_text


class PhishingEmailAgent:
    name = "phishing_email_agent"

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
        text_result = dispatch("analyze_text", text=clean.clean_text)

        # Check every embedded URL
        urls = extract_urls(clean.clean_text)
        url_results = [dispatch("check_url", url=u) for u in urls]

        # Check sender domain for typosquatting
        sender_flag = None
        if sender and "@" in sender:
            domain = sender.split("@")[-1].lower()
            check = dispatch("check_url", url=domain)
            if check["is_typosquat_suspect"]:
                sender_flag = f"sender_domain_typosquat:{check['closest_known_domain']}"

        verdict = dispatch(
            "risk_scorer",
            text_result=text_result,
            url_results=url_results,
            channel_hint="email",
        )
        return {
            "agent": self.name,
            "sanitizer_flags": clean.flags,
            "text_analysis": text_result,
            "url_analysis": url_results,
            "sender_flag": sender_flag,
            "risk": verdict,
        }
