"""Keeps a rolling memory of past interactions per user so repeated scam
attempts (e.g. the same caller phoning back) are flagged faster.

Each user gets a capped history deque (default 100 entries) to bound memory.
"""
import time
from collections import defaultdict, deque

_HIGH_RISK_VERDICTS = {"HIGH_RISK_SCAM", "LIKELY_SCAM"}
_MAX_HISTORY = 100


class RiskMemoryAgent:
    """In-memory rolling risk history per user ID."""

    def __init__(self, max_history: int = _MAX_HISTORY):
        self._max = max_history
        self._history: dict[str, deque] = defaultdict(lambda: deque(maxlen=self._max))

    def record(self, user_id: str, source: str, verdict: str, score: int) -> None:
        """Append an interaction to a user's history."""
        self._history[user_id].append(
            {
                "ts": time.time(),
                "source": source,
                "verdict": verdict,
                "score": score,
            }
        )

    def repeat_offender_boost(self, user_id: str, lookback: int = 5) -> int:
        """
        Return an additive score boost if the user has recent high-risk hits.

        3+ bad hits in the last `lookback` → +15 pts
        1-2 bad hits                       → +5  pts
        0 bad hits                         → 0   pts
        """
        recent = list(self._history[user_id])[-lookback:]
        bad = [r for r in recent if r["verdict"] in _HIGH_RISK_VERDICTS]
        if len(bad) >= 3:
            return 15
        if len(bad) >= 1:
            return 5
        return 0

    def history(self, user_id: str) -> list[dict]:
        """Return a copy of the user's full history list."""
        return list(self._history[user_id])

    def summary(self, user_id: str) -> dict:
        """Return aggregated stats for a user."""
        hist = self.history(user_id)
        if not hist:
            return {"total": 0, "high_risk_count": 0, "avg_score": 0}
        high_risk = [h for h in hist if h["verdict"] in _HIGH_RISK_VERDICTS]
        return {
            "total": len(hist),
            "high_risk_count": len(high_risk),
            "avg_score": round(sum(h["score"] for h in hist) / len(hist), 1),
            "last_verdict": hist[-1]["verdict"],
        }
