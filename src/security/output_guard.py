"""Synthetic RAG output-security controls"""

import re
from dataclasses import dataclass


EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

SYNTHETIC_TOKEN_PATTERN = re.compile(
    r"\bSYNTH-TOKEN-[A-Za-z0-9_-]+\b"
)

ALLOWED_CLASSIFICATIONS = frozenset(
    {"PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"}
)


@dataclass(frozen=True)
class OutputGuardResult:
    allowed: bool
    reason: str
    content: str | None
    redactions: int


def protect_output(
    content: str,
    classification: str,
) -> OutputGuardResult:
    """Apply a limited synthetic output-disclosure policy."""

    if not isinstance(content, str) or not content.strip():
        return OutputGuardResult(
            False, "INVALID_OUTPUT", None, 0
        )

    if classification not in ALLOWED_CLASSIFICATIONS:
        return OutputGuardResult(
            False, "INVALID_CLASSIFICATION", None, 0
        )

    if classification == "RESTRICTED":
        return OutputGuardResult(
            False, "RESTRICTED_OUTPUT_BLOCKED", None, 0
        )

    sanitized, token_count = SYNTHETIC_TOKEN_PATTERN.subn(
        "[REDACTED_TOKEN]", content
    )

    sanitized, email_count = EMAIL_PATTERN.subn(
        "[REDACTED_EMAIL]", sanitized
    )

    redactions = token_count + email_count

    return OutputGuardResult(
        True,
        "OUTPUT_REDACTED" if redactions else "OUTPUT_APPROVED",
        sanitized,
        redactions,
    )