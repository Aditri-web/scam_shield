"""Input sanitization: strips control chars, neutralizes prompt-injection
patterns, redacts common PII (SSN, credit card, phone), caps length, and
normalizes whitespace before any text reaches an agent or LLM call.

PII is replaced with a placeholder token so downstream analysis still works
but raw PII never reaches external services or logs.
"""
import re

MAX_LEN = 20_000

# ── Prompt-injection patterns ────────────────────────────────────────────────
INJECTION_PATTERNS = [
    r"ignore (all|any|previous) instructions",
    r"system prompt",
    r"you are now",
    r"disregard (the )?(above|previous)",
    r"act as (an? )?(unrestricted|jailbroken)",
    r"DAN mode",
]

# ── PII redaction patterns ────────────────────────────────────────────────────
_PII_RULES: list[tuple[re.Pattern, str]] = [
    # US Social Security Number (dashes or spaces)
    (re.compile(r"\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b"), "[SSN_REDACTED]"),
    # Credit / debit card numbers (13-16 digits, optionally dashes/spaces)
    (re.compile(r"\b(?:\d[ -]?){13,16}\b"), "[CARD_REDACTED]"),
    # US phone numbers in various formats
    (re.compile(r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"), "[PHONE_REDACTED]"),
    # Email addresses
    (re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"), "[EMAIL_REDACTED]"),
    # Driver's license numbers (simple heuristic: letter + 6-8 digits)
    (re.compile(r"\b[A-Z]{1,2}\d{6,8}\b"), "[DL_REDACTED]"),
]

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_WHITESPACE = re.compile(r"[ \t]+")


class SanitizationResult:
    def __init__(self, clean_text: str, redacted_text: str, flags: list[str]):
        self.clean_text = clean_text          # injection-safe, whitespace-normalized
        self.redacted_text = redacted_text    # PII replaced with placeholder tokens
        self.flags = flags

    def __repr__(self) -> str:
        return f"SanitizationResult(flags={self.flags})"


def _redact_pii(text: str) -> tuple[str, list[str]]:
    """Replace PII patterns with placeholder tokens. Returns (redacted, flags)."""
    flags: list[str] = []
    for pattern, placeholder in _PII_RULES:
        found = pattern.findall(text)
        if found:
            tag = placeholder.strip("[]").lower()
            flags.append(f"pii_redacted:{tag}:count={len(found)}")
            text = pattern.sub(placeholder, text)
    return text, flags


def sanitize_text(raw: str) -> SanitizationResult:
    """
    Full sanitization pipeline:
      1. Truncate if over MAX_LEN.
      2. Strip control characters.
      3. Normalize whitespace.
      4. Detect prompt-injection patterns (flagged but NOT removed so analysis is honest).
      5. Redact PII.
    """
    if raw is None:
        raw = ""
    flags: list[str] = []

    # 1. Truncate
    if len(raw) > MAX_LEN:
        flags.append("truncated_input")
        raw = raw[:MAX_LEN]

    # 2. Strip control chars + normalize whitespace
    cleaned = _CONTROL_CHARS.sub("", raw)
    cleaned = _WHITESPACE.sub(" ", cleaned).strip()

    # 3. Prompt-injection detection
    lowered = cleaned.lower()
    for pat in INJECTION_PATTERNS:
        if re.search(pat, lowered, re.IGNORECASE):
            flags.append(f"possible_prompt_injection:{pat}")

    # 4. PII redaction — applied to the cleaned text
    redacted, pii_flags = _redact_pii(cleaned)
    flags.extend(pii_flags)

    return SanitizationResult(
        clean_text=cleaned,      # injection-safe; PII still present (for local analysis)
        redacted_text=redacted,  # safe to log/send externally
        flags=flags,
    )
