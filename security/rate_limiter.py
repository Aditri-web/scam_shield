"""Simple in-memory sliding-window rate limiter to protect agent/tool
endpoints from abuse (e.g. someone hammering the URL checker).

Thread-safe via a per-key Lock strategy.
"""
import time
from collections import defaultdict, deque
from threading import Lock


class RateLimiter:
    """
    Sliding-window rate limiter.

    Args:
        max_calls: Maximum number of calls allowed per key per window.
        window_seconds: Duration of the sliding window in seconds.
    """

    def __init__(self, max_calls: int = 30, window_seconds: int = 60):
        self.max_calls = max_calls
        self.window_seconds = window_seconds
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = Lock()

    def _evict(self, key: str, now: float) -> None:
        """Remove stale timestamps outside the current window."""
        q = self._hits[key]
        while q and now - q[0] > self.window_seconds:
            q.popleft()

    def allow(self, key: str) -> bool:
        """Return True if the request is within the rate limit, False otherwise."""
        now = time.time()
        with self._lock:
            self._evict(key, now)
            if len(self._hits[key]) >= self.max_calls:
                return False
            self._hits[key].append(now)
            return True

    def remaining(self, key: str) -> int:
        """Return how many calls remain in the current window for `key`."""
        now = time.time()
        with self._lock:
            self._evict(key, now)
            return max(0, self.max_calls - len(self._hits[key]))

    def reset(self, key: str) -> None:
        """Manually clear the hit history for a key (useful in tests)."""
        with self._lock:
            self._hits[key].clear()
