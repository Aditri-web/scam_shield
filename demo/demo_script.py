"""Demo script — runs all three sample inputs through GuardianAgent and
prints a formatted report. Run from the scamshield-ai/ root:

    python demo/demo_script.py
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from agents.guardian_agent import GuardianAgent

SAMPLES = [
    ("elderly_user_1", "call",      "sample_inputs/scam_call_transcript.txt", None),
    ("elderly_user_1", "email",     "sample_inputs/phishing_email.txt",       "support@amaz0n-secure-login.xyz"),
    ("elderly_user_2", "financial", "sample_inputs/fake_investment.txt",       None),
]

_VERDICT_COLORS = {
    "HIGH_RISK_SCAM": "\033[91m",   # bright red
    "LIKELY_SCAM":    "\033[93m",   # yellow
    "SUSPICIOUS":     "\033[33m",   # orange-ish
    "LIKELY_SAFE":    "\033[92m",   # green
}
_RESET = "\033[0m"


def _color(verdict: str, text: str) -> str:
    return f"{_VERDICT_COLORS.get(verdict, '')}{text}{_RESET}"


def run_demo():
    guardian = GuardianAgent(guardian_contact="+1-555-0100")
    here = os.path.dirname(__file__)

    print("\n" + "═" * 70)
    print("  ScamShield AI — Multi-Agent Demo")
    print("═" * 70 + "\n")

    for user_id, input_type, rel_path, sender in SAMPLES:
        fpath = os.path.join(here, rel_path)
        with open(fpath) as f:
            text = f.read()

        start = time.perf_counter()
        result = guardian.process(
            user_id=user_id, input_type=input_type, text=text, sender=sender
        )
        elapsed = time.perf_counter() - start

        risk = result["agent_result"]["risk"]
        verdict = risk["verdict"]
        score = risk["final_score"]
        categories = list(result["agent_result"]["text_analysis"].get("matched_categories", {}).keys())
        notified = result["notification"].get("notified", False)
        mem = result.get("memory_summary", {})

        print(f"User     : {user_id}")
        print(f"Channel  : {input_type.upper()}")
        print(f"Verdict  : {_color(verdict, verdict)}")
        print(f"Score    : {score}/100")
        print(f"Categories flagged : {', '.join(categories) if categories else 'none'}")
        print(f"Guardian notified  : {'YES ✓' if notified else 'no'}")
        print(f"Memory (history)   : {mem.get('total', 0)} interactions, "
              f"{mem.get('high_risk_count', 0)} high-risk")
        print(f"Processing time    : {elapsed*1000:.1f} ms")
        print("─" * 70 + "\n")

    print("Audit log: scamshield_audit.log")
    print("Notification log: family_notifications.log")
    print("\nRun `python -m cli.scamshield_cli verify-audit` to check log integrity.\n")


if __name__ == "__main__":
    run_demo()
