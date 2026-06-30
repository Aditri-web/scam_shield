"""Decides whether/how to alert a designated family member or guardian
when a high-risk scam is detected, and sends the (simulated) alert.

Notification is triggered when `final_score >= SEVERITY_THRESHOLD`.
In production swap notification_tool's stubs for real Twilio/SendGrid calls.
"""
from mcp_server.server import dispatch

SEVERITY_THRESHOLD = 60  # out of 100


class FamilyNotificationAgent:
    name = "family_notification_agent"

    def maybe_notify(
        self,
        user_id: str,
        guardian_contact: str,
        source_agent: str,
        risk: dict,
    ) -> dict:
        """
        Conditionally alert the guardian contact.

        Args:
            user_id: ID of the protected user.
            guardian_contact: Phone or email of the trusted guardian.
            source_agent: Name of the specialist agent that raised the alert.
            risk: Final risk dict from risk_scorer.

        Returns a dict with `notified` bool and either `reason` or `delivery`.
        """
        score = risk.get("final_score", 0)
        verdict = risk.get("verdict", "UNKNOWN")

        if score < SEVERITY_THRESHOLD:
            return {"notified": False, "reason": "below_threshold", "score": score}

        message = (
            f"ScamShield Alert: {user_id} may be targeted by a scam via {source_agent}. "
            f"Verdict: {verdict} (score {score}/100). Please check in with them immediately."
        )
        result = dispatch(
            "notification_tool",
            recipient=guardian_contact,
            message=message,
            severity=verdict,
            channel="sms",
        )
        return {"notified": True, "delivery": result}
