"""Tests for FinancialScamAgent."""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from agents.financial_scam_agent import FinancialScamAgent


@pytest.fixture
def agent():
    return FinancialScamAgent()


def test_guaranteed_returns_flagged(agent):
    text = "Guaranteed 20% monthly returns, no risk investment, send the processing fee in Bitcoin."
    result = agent.analyze(text)
    assert result["risk"]["final_score"] >= 35


def test_neutral_text_low_score(agent):
    result = agent.analyze("Quarterly report attached, let me know if you have questions.")
    assert result["risk"]["final_score"] < 30


def test_pig_butchering_pattern_detected(agent):
    text = "Our pig butchering platform guarantees returns. Deposit to activate your account."
    result = agent.analyze(text)
    assert result["risk"]["final_score"] > 20
    fin_specific = result["text_analysis"]["matched_categories"].get("financial_specific", [])
    assert len(fin_specific) >= 1


def test_combined_scam_terms_high_score(agent):
    text = (
        "Advance fee required. Guaranteed returns. Bitcoin payment. "
        "Risk-free investment. Double your money. Processing fee needed."
    )
    result = agent.analyze(text)
    assert result["risk"]["verdict"] in ("LIKELY_SCAM", "HIGH_RISK_SCAM")


def test_sanitizer_flags_present(agent):
    # Very long text should trigger truncated_input flag
    text = "risk-free investment. " * 2000
    result = agent.analyze(text)
    assert "truncated_input" in result["sanitizer_flags"]
