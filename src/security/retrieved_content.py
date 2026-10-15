"""Security screening for retrieved synthetic RAG content."""

import re
from dataclasses import dataclass


INJECTION_PATTERNS = (
    re.compile(
        r"ignore\s+(all\s+)?previous\s+instructions",
        re.IGNORECASE,
    ),
    re.compile(
        r"disregard\s+(all\s+)?(prior|previous)\s+instructions",
        re.IGNORECASE,
    ),
    re.compile(
        r"you\s+are\s+now\s+(a|an)\s+",
        re.IGNORECASE,
    ),
    re.compile(
        r"(system|developer)\s+message\s*:",
        re.IGNORECASE,
    ),
    re.compile(
        r"reveal\s+(the\s+)?(system\s+prompt|hidden\s+instructions)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:append|insert|include|add)\b.{0,100}"
        r"\b(?:phrase|marker|string|token)\b",
        re.I | re.S,
    ),
    re.compile(
        r"\b(?:evaluation|compliance)\b.{0,100}"
        r"\b(?:required|must|mandatory)\b",
        re.I | re.S,
    ),
)


@dataclass(frozen=True)
class ContentScreeningResult:
    accepted: bool
    reason: str
    content: str | None


def screen_retrieved_content(
    content: str,
) -> ContentScreeningResult:
    """Reject selected instruction patterns in retrieved content."""

    if not isinstance(content, str):
        return ContentScreeningResult(
            False, "INVALID_CONTENT", None
        )

    if not content.strip():
        return ContentScreeningResult(
            False, "EMPTY_CONTENT", None
        )

    for pattern in INJECTION_PATTERNS:
        if pattern.search(content):
            return ContentScreeningResult(
                False, "SUSPECTED_PROMPT_INJECTION", None
            )

    return ContentScreeningResult(
        True, "CONTENT_SCREENING_PASSED", content
    )