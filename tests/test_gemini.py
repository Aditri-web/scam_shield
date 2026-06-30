"""Tests for GeminiAnalyzer and Gemini integrations."""
import os
import sys
from unittest.mock import MagicMock, patch
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from agents.gemini_analyzer import GeminiAnalyzer, ScamVerdictSchema
from agents.call_protection_agent import CallProtectionAgent
from agents.phishing_email_agent import PhishingEmailAgent
from agents.financial_scam_agent import FinancialScamAgent


@pytest.fixture
def mock_gemini_client():
    with patch("agents.gemini_analyzer.genai.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        yield mock_client


@patch.dict(os.environ, {"GEMINI_API_KEY": "fake_key"})
@patch("agents.gemini_analyzer._HAS_GENAI", True)
def test_gemini_analyzer_success(mock_gemini_client):
    # Mocking Client response
    mock_response = MagicMock()
    mock_response.text = (
        '{"score": 90, "verdict": "HIGH_RISK_SCAM", "reasoning": "Urgent gift cards requested", "red_flags": ["gift cards"]}'
    )
    mock_gemini_client.models.generate_content.return_value = mock_response

    analyzer = GeminiAnalyzer()
    assert analyzer.is_enabled is True

    result = analyzer.analyze("Send gift cards now")
    assert result is not None
    assert result.score == 90
    assert result.verdict == "HIGH_RISK_SCAM"
    assert result.reasoning == "Urgent gift cards requested"
    assert "gift cards" in result.red_flags


@patch.dict(os.environ, {"GEMINI_API_KEY": "fake_key"})
@patch("agents.gemini_analyzer._HAS_GENAI", True)
def test_call_protection_agent_gemini(mock_gemini_client):
    mock_response = MagicMock()
    mock_response.text = (
        '{"score": 85, "verdict": "HIGH_RISK_SCAM", "reasoning": "SSN suspension voice scam", "red_flags": ["SSN suspended"]}'
    )
    mock_gemini_client.models.generate_content.return_value = mock_response

    agent = CallProtectionAgent()
    assert agent.gemini.is_enabled is True

    result = agent.analyze("Your SSN is suspended")
    assert result["gemini_analyzed"] is True
    assert result["risk"]["final_score"] == 85
    assert result["risk"]["verdict"] == "HIGH_RISK_SCAM"


@patch.dict(os.environ, {"GEMINI_API_KEY": "fake_key"})
@patch("agents.gemini_analyzer._HAS_GENAI", True)
def test_phishing_email_agent_gemini(mock_gemini_client):
    mock_response = MagicMock()
    mock_response.text = (
        '{"score": 75, "verdict": "LIKELY_SCAM", "reasoning": "Typosquatting sender domain", "red_flags": ["typosquat"]}'
    )
    mock_gemini_client.models.generate_content.return_value = mock_response

    agent = PhishingEmailAgent()
    assert agent.gemini.is_enabled is True

    result = agent.analyze("Click here http://amaz0n.xyz", sender="support@amaz0n.xyz")
    assert result["gemini_analyzed"] is True
    assert result["risk"]["final_score"] == 75
    assert result["risk"]["verdict"] == "LIKELY_SCAM"


@patch.dict(os.environ, {"GEMINI_API_KEY": "fake_key"})
@patch("agents.gemini_analyzer._HAS_GENAI", True)
def test_financial_scam_agent_gemini(mock_gemini_client):
    mock_response = MagicMock()
    mock_response.text = (
        '{"score": 95, "verdict": "HIGH_RISK_SCAM", "reasoning": "Guaranteed crypto returns scam", "red_flags": ["guaranteed returns"]}'
    )
    mock_gemini_client.models.generate_content.return_value = mock_response

    agent = FinancialScamAgent()
    assert agent.gemini.is_enabled is True

    result = agent.analyze("Guaranteed 20% monthly returns in Bitcoin")
    assert result["gemini_analyzed"] is True
    assert result["risk"]["final_score"] == 95
    assert result["risk"]["verdict"] == "HIGH_RISK_SCAM"
