"""Local Ollama gateway with output protection"""

import json
import urllib.request
from dataclasses import dataclass

from src.security.output_guard import protect_output


OLLAMA_URL = "http://127.0.0.1:11434/api/chat"
MODEL = "qwen2.5:3b"


@dataclass(frozen=True)
class ProtectedModelResult:
    allowed: bool
    reason: str
    content: str | None
    redactions: int


def generate_protected_response(
    messages: tuple[dict[str, str], ...],
    classification: str,
) -> ProtectedModelResult:
    """Generate locally and apply output controls before release."""

    if not isinstance(messages, tuple) or not messages:
        return ProtectedModelResult(
            False, "INVALID_CONTEXT", None, 0
        )

    if any(
        not isinstance(message, dict)
        or message.get("role") not in {"system", "user", "assistant"}
        or not isinstance(message.get("content"), str)
        for message in messages
    ):
        return ProtectedModelResult(
            False, "INVALID_CONTEXT", None, 0
        )

    if classification not in {
        "PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"
    }:
        return ProtectedModelResult(
            False, "INVALID_CLASSIFICATION", None, 0
        )

    if classification == "RESTRICTED":
        return ProtectedModelResult(
            False, "RESTRICTED_OUTPUT_BLOCKED", None, 0
        )

    payload = {
        "model": MODEL,
        "messages": list(messages),
        "stream": False,
        "options": {
            "temperature": 0,
            "num_predict": 128,
        },
    }

    request = urllib.request.Request(
        OLLAMA_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(
            request, timeout=120
        ) as response:
            result = json.load(response)

        raw_output = result["message"]["content"]

    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
    ):
        return ProtectedModelResult(
            False, "MODEL_GENERATION_FAILED", None, 0
        )

    protected = protect_output(
        raw_output,
        classification,
    )

    return ProtectedModelResult(
        protected.allowed,
        protected.reason,
        protected.content,
        protected.redactions,
    )