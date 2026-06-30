"""MCP tool: notification_tool — simulates sending a guardian/family alert.

In production swap the _send_* helpers for real providers:
  - SMS: Twilio
  - Email: SendGrid / SES
  - Push: Firebase Cloud Messaging

Environment variables:
  TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM_NUMBER
  SENDGRID_API_KEY, ALERT_FROM_EMAIL
"""
import json
import os
import time

NOTIFICATION_LOG = os.getenv("NOTIFICATION_LOG", "family_notifications.log")


def _send_sms_simulated(recipient: str, message: str) -> str:
    """Stub — replace with Twilio client in production."""
    return "simulated_sms"


def _send_email_simulated(recipient: str, message: str, severity: str) -> str:
    """Stub — replace with SendGrid client in production."""
    return "simulated_email"


_CHANNEL_DISPATCH = {
    "sms": _send_sms_simulated,
    "email": _send_email_simulated,
}


def notification_tool(
    recipient: str,
    message: str,
    severity: str,
    channel: str = "sms",
) -> dict:
    """
    Send a guardian/family alert about a detected scam.

    Args:
        recipient: Phone number (sms) or email address.
        message: Human-readable alert body.
        severity: One of HIGH_RISK_SCAM, LIKELY_SCAM, SUSPICIOUS.
        channel: Delivery channel — 'sms' or 'email'.

    Returns a dict with delivery status and timestamp.
    """
    sender_fn = _CHANNEL_DISPATCH.get(channel, _send_sms_simulated)
    delivery_id = sender_fn(recipient, message)

    payload = {
        "ts": time.time(),
        "recipient": recipient,
        "channel": channel,
        "severity": severity,
        "message": message,
        "delivery_id": delivery_id,
        "status": "sent_simulated",
    }
    with open(NOTIFICATION_LOG, "a") as f:
        f.write(json.dumps(payload) + "\n")
    return payload
