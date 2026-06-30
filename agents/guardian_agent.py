"""GuardianAgent: top-level orchestrator.

Routes input to the right specialist agent(s), aggregates the risk verdict,
updates memory, and triggers family notification when warranted.

Google ADK integration
──────────────────────
`GuardianADKAgent` wraps GuardianAgent in a google.adk.agents.Agent subclass
so it participates in richer planning/tool-calling loops. When `google-adk`
is not installed, it degrades gracefully to plain GuardianAgent.

Usage (ADK):
    from agents.guardian_agent import GuardianADKAgent
    agent = GuardianADKAgent()
    response = agent.run("Scan this email for scams: <email text here>")

Usage (direct):
    from agents.guardian_agent import GuardianAgent
    guardian = GuardianAgent()
    result = guardian.process(user_id="alice", input_type="email", text="...")
"""
import os
import sys

from agents.call_protection_agent import CallProtectionAgent
from agents.phishing_email_agent import PhishingEmailAgent
from agents.financial_scam_agent import FinancialScamAgent
from agents.risk_memory_agent import RiskMemoryAgent
from agents.family_notification_agent import FamilyNotificationAgent
from security.rate_limiter import RateLimiter
from security.audit_logger import AuditLogger

_VALID_TYPES = {"call", "email", "financial"}


class GuardianAgent:
    """
    Top-level orchestrator for ScamShield AI.

    Responsibilities:
    - Rate-limit incoming requests per user.
    - Route to the correct specialist agent.
    - Apply the repeat-offender memory boost.
    - Trigger family/guardian notification.
    - Append a hash-chained audit log entry.
    """

    def __init__(
        self,
        guardian_contact: str = "+1-555-0100",
        max_calls: int = 30,
        window_seconds: int = 60,
        audit_path: str = "scamshield_audit.log",
    ):
        self.call_agent = CallProtectionAgent()
        self.email_agent = PhishingEmailAgent()
        self.financial_agent = FinancialScamAgent()
        self.memory = RiskMemoryAgent()
        self.notifier = FamilyNotificationAgent()
        self.rate_limiter = RateLimiter(max_calls=max_calls, window_seconds=window_seconds)
        self.audit = AuditLogger(path=audit_path)
        self.guardian_contact = guardian_contact

    # ── Routing ───────────────────────────────────────────────────────────────

    def _route(self, input_type: str):
        routes = {
            "call": self.call_agent,
            "email": self.email_agent,
            "financial": self.financial_agent,
        }
        agent = routes.get(input_type)
        if agent is None:
            raise ValueError(
                f"Unknown input_type {input_type!r}. Choose from: {_VALID_TYPES}"
            )
        return agent

    # ── Main entrypoint ───────────────────────────────────────────────────────

    def process(
        self,
        user_id: str,
        input_type: str,
        text: str,
        sender: str | None = None,
    ) -> dict:
        """
        Run the full multi-agent pipeline on a piece of content.

        Args:
            user_id:    Identifier for the protected user.
            input_type: One of 'call', 'email', 'financial'.
            text:       Raw content to analyse.
            sender:     Sender address (only meaningful for email).

        Returns a comprehensive result dict.
        """
        if not self.rate_limiter.allow(user_id):
            return {
                "error": "rate_limited",
                "user_id": user_id,
                "remaining": self.rate_limiter.remaining(user_id),
            }

        agent = self._route(input_type)
        if input_type == "email":
            result = agent.analyze(text, sender=sender)
        else:
            result = agent.analyze(text)

        risk = result["risk"]

        # Apply repeat-offender memory boost
        boost = self.memory.repeat_offender_boost(user_id)
        if boost:
            risk["final_score"] = min(100, risk["final_score"] + boost)
            risk["repeat_offender_boost"] = boost
            # Re-compute verdict after boost
            fs = risk["final_score"]
            if fs >= 80:
                risk["verdict"] = "HIGH_RISK_SCAM"
            elif fs >= 60:
                risk["verdict"] = "LIKELY_SCAM"
            elif fs >= 30:
                risk["verdict"] = "SUSPICIOUS"

        # Record this interaction in memory
        self.memory.record(user_id, input_type, risk["verdict"], risk["final_score"])

        # Conditionally notify guardian
        notify_result = self.notifier.maybe_notify(
            user_id=user_id,
            guardian_contact=self.guardian_contact,
            source_agent=agent.name,
            risk=risk,
        )

        # Tamper-evident audit log
        self.audit.log(
            event_type="scan_completed",
            detail={
                "input_type": input_type,
                "risk": risk,
                "notify": notify_result,
            },
            user_id=user_id,
        )

        return {
            "user_id": user_id,
            "input_type": input_type,
            "agent_result": result,
            "memory_summary": self.memory.summary(user_id),
            "notification": notify_result,
        }


# ── Google ADK wrapper ─────────────────────────────────────────────────────────

def _build_adk_agent() -> type | None:
    """
    Attempt to build an ADK-wrapped GuardianAgent class.

    Returns the class if google-adk is installed, None otherwise.
    """
    try:
        from google.adk.agents import Agent
        from google.adk.tools import FunctionTool
        from mcp_server.server import dispatch, list_tools

        # Expose all MCP tools as ADK FunctionTools
        _adk_tools = []
        for tool_def in list_tools():
            name = tool_def["name"]
            fn = __import__(
                f"mcp_server.tools.{name}", fromlist=[name]
            ).__dict__.get(name)
            if fn:
                _adk_tools.append(FunctionTool(fn))

        class _GuardianADKAgent(Agent):
            """
            ADK-wrapped GuardianAgent.

            The LLM orchestrator has access to the four MCP tools and delegates
            to GuardianAgent for final verdict computation.
            """

            def __init__(self, guardian_contact: str = "+1-555-0100", **kwargs):
                super().__init__(
                    name="guardian_agent",
                    description=(
                        "ScamShield Guardian: orchestrates scam detection across "
                        "calls, phishing emails, and financial fraud."
                    ),
                    tools=_adk_tools,
                    model=os.getenv("GOOGLE_MODEL", "gemini-2.0-flash"),
                    **kwargs,
                )
                self._guardian = GuardianAgent(guardian_contact=guardian_contact)

            def process(self, user_id: str, input_type: str, text: str, **kwargs) -> dict:
                """Delegate to the underlying GuardianAgent for deterministic processing."""
                return self._guardian.process(
                    user_id=user_id, input_type=input_type, text=text, **kwargs
                )

        return _GuardianADKAgent
    except ImportError:
        return None


_GuardianADKAgentClass = _build_adk_agent()

if _GuardianADKAgentClass is not None:
    GuardianADKAgent = _GuardianADKAgentClass
else:
    # Provide a no-op shim so imports don't break
    class GuardianADKAgent(GuardianAgent):  # type: ignore[no-redef]
        """
        Shim: google-adk not installed.
        Falls back to plain GuardianAgent behaviour.

        Install google-adk to enable LLM-powered orchestration:
          pip install google-adk
        """
        pass
