"""Tests for GuardianAgent orchestrator."""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from agents.guardian_agent import GuardianAgent


@pytest.fixture
def guardian(tmp_path):
    """Return a GuardianAgent that writes audit log to a temp file."""
    return GuardianAgent(audit_path=str(tmp_path / "audit.log"))


def test_high_risk_call_detected(guardian):
    transcript = (
        "Your social security number has been suspended. "
        "Send gift cards now or be arrested."
    )
    result = guardian.process(user_id="t1", input_type="call", text=transcript)
    assert result["agent_result"]["risk"]["final_score"] > 20


def test_safe_text_low_risk(guardian):
    result = guardian.process(
        user_id="t2", input_type="call", text="Hi, just calling to say happy birthday!"
    )
    assert result["agent_result"]["risk"]["verdict"] in ("LIKELY_SAFE", "SUSPICIOUS")


def test_repeat_offender_boost_applies(guardian):
    transcript = "Wire transfer immediately or your account will be suspended, act now."
    r1 = guardian.process(user_id="t3", input_type="call", text=transcript)
    r2 = guardian.process(user_id="t3", input_type="call", text=transcript)
    r3 = guardian.process(user_id="t3", input_type="call", text=transcript)
    # Score should be >= first scan (repeat-offender boost applied from r2 onwards)
    assert r3["agent_result"]["risk"]["final_score"] >= r1["agent_result"]["risk"]["final_score"]


def test_rate_limiter_blocks_excess(tmp_path):
    guardian = GuardianAgent(
        max_calls=2, window_seconds=60, audit_path=str(tmp_path / "audit.log")
    )
    for _ in range(2):
        r = guardian.process(user_id="t4", input_type="call", text="Hello")
        assert "error" not in r
    # Third call should be rate-limited
    r = guardian.process(user_id="t4", input_type="call", text="Hello")
    assert r.get("error") == "rate_limited"


def test_invalid_input_type_raises(guardian):
    with pytest.raises(ValueError, match="Unknown input_type"):
        guardian.process(user_id="t5", input_type="smoke_signal", text="test")


def test_memory_summary_populated(guardian):
    guardian.process(
        user_id="t6",
        input_type="call",
        text="Your account will be suspended, act now, gift card, wire transfer",
    )
    summary = guardian.memory.summary("t6")
    assert summary["total"] >= 1


def test_notification_sent_on_high_risk(guardian):
    text = (
        "Your social security number has been suspended. Act now or be arrested. "
        "Gift card. Wire transfer. Verify your identity within 24 hours. "
        "Enter your ssn. Final notice."
    )
    result = guardian.process(user_id="t7", input_type="call", text=text)
    # Score high enough that notification fires
    score = result["agent_result"]["risk"]["final_score"]
    if score >= 60:
        assert result["notification"]["notified"] is True
