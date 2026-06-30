"""Tests for PhishingEmailAgent."""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from agents.phishing_email_agent import PhishingEmailAgent


@pytest.fixture
def agent():
    return PhishingEmailAgent()


def test_typosquat_url_flagged(agent):
    text = "Verify now: http://amaz0n-secure-login.xyz/verify your password"
    result = agent.analyze(text, sender="support@amaz0n-secure-login.xyz")
    assert result["risk"]["final_score"] > 0
    assert any(u["is_typosquat_suspect"] for u in result["url_analysis"])


def test_legit_domain_not_flagged(agent):
    text = "Here is your receipt: https://amazon.com/orders/123"
    result = agent.analyze(text, sender="orders@amazon.com")
    assert all(not u["is_typosquat_suspect"] for u in result["url_analysis"])


def test_suspicious_tld_flagged(agent):
    text = "Click here immediately: http://paypal-secure.top/confirm"
    result = agent.analyze(text)
    url_flags = [flag for u in result["url_analysis"] for flag in u["flags"]]
    assert "suspicious_tld" in url_flags


def test_sender_flag_for_typosquat_domain(agent):
    text = "Please verify your account."
    result = agent.analyze(text, sender="noreply@amaz0n.xyz")
    assert result["sender_flag"] is not None
    assert "typosquat" in result["sender_flag"]


def test_no_urls_in_text(agent):
    text = "Your account needs attention."
    result = agent.analyze(text)
    assert result["url_analysis"] == []


def test_multiple_urls_aggregated(agent):
    text = (
        "Click http://paypa1.xyz or http://amaz0n.top for your reward. "
        "Or visit https://amazon.com for the real thing."
    )
    result = agent.analyze(text)
    assert len(result["url_analysis"]) == 3
    suspicious = [u for u in result["url_analysis"] if u["url_risk_score"] > 0]
    assert len(suspicious) >= 2


def test_credential_harvest_text_scores_high(agent):
    text = (
        "Final notice: click here to verify. Confirm your password. "
        "Update your billing information. Your card has been locked."
    )
    result = agent.analyze(text)
    assert result["risk"]["final_score"] >= 30
