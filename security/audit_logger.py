"""Append-only, tamper-evident audit log.

Each entry is SHA-256 hash-chained to the previous one so any deletion or
edit of a past entry is detectable via `verify_chain()`.

SIEM integration: set the SIEM_WEBHOOK_URL + SIEM_API_KEY environment
variables to ship every log entry to an external SIEM in real-time.
The shipping is fire-and-forget (non-blocking) so it never slows the
main analysis pipeline.
"""
import json
import hashlib
import os
import threading
import time
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import URLError

_SIEM_URL = os.getenv("SIEM_WEBHOOK_URL", "")
_SIEM_KEY = os.getenv("SIEM_API_KEY", "")


def _ship_to_siem(entry: dict) -> None:
    """Non-blocking SIEM delivery — called in a daemon thread."""
    if not _SIEM_URL:
        return
    try:
        payload = json.dumps(entry).encode()
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {_SIEM_KEY}",
            "X-Source": "scamshield-ai",
        }
        req = Request(_SIEM_URL, data=payload, headers=headers, method="POST")
        with urlopen(req, timeout=3):
            pass
    except (URLError, Exception):
        # Silently swallow — audit integrity must not depend on SIEM reachability
        pass


class AuditLogger:
    """
    Append-only hash-chained audit log.

    Args:
        path: File path for the local append-only log.
    """

    def __init__(self, path: str = "scamshield_audit.log"):
        self.path = path
        self._last_hash = self._load_last_hash()
        self._write_lock = threading.Lock()

    # ── Internal helpers ─────────────────────────────────────────────────────

    def _load_last_hash(self) -> str:
        if not os.path.exists(self.path):
            return "0" * 64
        last = "0" * 64
        with open(self.path, "r") as f:
            for line in f:
                try:
                    last = json.loads(line)["hash"]
                except Exception:
                    continue
        return last

    # ── Public API ────────────────────────────────────────────────────────────

    def log(
        self,
        event_type: str,
        detail: dict[str, Any],
        user_id: str = "anonymous",
    ) -> dict:
        """
        Append a hash-chained audit entry.

        Returns the full entry dict (including `hash`).
        """
        entry: dict[str, Any] = {
            "ts": time.time(),
            "event_type": event_type,
            "user_id": user_id,
            "detail": detail,
            "prev_hash": self._last_hash,
        }
        payload = json.dumps(entry, sort_keys=True).encode()
        entry["hash"] = hashlib.sha256(self._last_hash.encode() + payload).hexdigest()

        with self._write_lock:
            with open(self.path, "a") as f:
                f.write(json.dumps(entry) + "\n")
            self._last_hash = entry["hash"]

        # Fire-and-forget SIEM delivery
        t = threading.Thread(target=_ship_to_siem, args=(entry,), daemon=True)
        t.start()

        return entry

    def verify_chain(self) -> bool:
        """
        Verify the entire hash chain from the beginning.

        Returns True if no tampering is detected, False otherwise.
        """
        prev = "0" * 64
        if not os.path.exists(self.path):
            return True
        with open(self.path) as f:
            for line in f:
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    return False
                claimed_hash = entry.pop("hash")
                payload = json.dumps(entry, sort_keys=True).encode()
                expected = hashlib.sha256(prev.encode() + payload).hexdigest()
                if expected != claimed_hash or entry["prev_hash"] != prev:
                    return False
                prev = claimed_hash
        return True

    def tail(self, n: int = 20) -> list[dict]:
        """Return the last `n` log entries."""
        if not os.path.exists(self.path):
            return []
        with open(self.path) as f:
            lines = f.readlines()
        entries = []
        for line in lines[-n:]:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return entries
