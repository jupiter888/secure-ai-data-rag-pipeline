"""Structured security-event recording for the synthetic RAG lab"""

from dataclasses import dataclass, field
from datetime import datetime, timezone


ALLOWED_EVENT_TYPES = frozenset({
    "INGESTION_DECISION",
    "RETRIEVAL_DECISION",
    "CONTENT_SCREENING_DECISION",
    "MODEL_GENERATION_DECISION",
    "OUTPUT_PROTECTION_DECISION",
})

ALLOWED_OUTCOMES = frozenset({
    "ALLOWED",
    "DENIED",
    "REDACTED",
    "ERROR",
})


@dataclass(frozen=True)
class SecurityEvent:
    timestamp: str
    event_type: str
    outcome: str
    reason: str
    document_id: str | None


@dataclass
class SecurityEventRecorder:
    """Record metadata-only security events in memory."""

    events: list[SecurityEvent] = field(default_factory=list)

    def record(
        self,
        event_type: str,
        outcome: str,
        reason: str,
        document_id: str | None = None,
    ) -> SecurityEvent:
        if event_type not in ALLOWED_EVENT_TYPES:
            raise ValueError("Unsupported security event type.")

        if outcome not in ALLOWED_OUTCOMES:
            raise ValueError("Unsupported security event outcome.")

        if (
            not isinstance(reason, str)
            or not reason
            or len(reason) > 128
            or not reason.replace("_", "").isalnum()
        ):
            raise ValueError("Invalid security event reason.")

        if document_id is not None and (
            not isinstance(document_id, str)
            or not document_id
            or len(document_id) > 64
            or not all(
                char.isascii() and (
                    char.isalnum() or char in "_-"
                )
                for char in document_id
            )
        ):
            raise ValueError("Invalid document identifier.")

        event = SecurityEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            outcome=outcome,
            reason=reason,
            document_id=document_id,
        )

        self.events.append(event)
        return event