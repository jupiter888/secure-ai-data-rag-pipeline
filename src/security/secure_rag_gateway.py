"""Unified authorization-first RAG execution gateway"""

from dataclasses import dataclass, field

from src.retrieval.authorization import Principal
from src.security.secure_context_pipeline import SecureContextPipeline
from src.security.protected_model_gateway import (
    generate_protected_response,
)
from src.security.security_events import SecurityEventRecorder


@dataclass(frozen=True)
class SecureRAGResult:
    allowed: bool
    reason: str
    content: str | None
    redactions: int


@dataclass
class SecureRAGGateway:
    """Coordinate authorized retrieval, generation, and event recording."""

    context_pipeline: SecureContextPipeline
    event_recorder: SecurityEventRecorder = field(
        default_factory=SecurityEventRecorder
    )

    def execute(
        self,
        principal: Principal,
        document_id: str,
        question: str,
    ) -> SecureRAGResult:
        """Deny requests unless secure context preparation succeeds."""

        context = self.context_pipeline.prepare(
            principal=principal,
            document_id=document_id,
            question=question,
        )

        if not context.accepted:
            event_type = (
                "CONTENT_SCREENING_DECISION"
                if context.reason == "SUSPECTED_PROMPT_INJECTION"
                else "RETRIEVAL_DECISION"
            )

            self.event_recorder.record(
                event_type=event_type,
                outcome="DENIED",
                reason=context.reason,
            )

            return SecureRAGResult(
                False, context.reason, None, 0
            )

        ingestion = (
            self.context_pipeline
            .retrieval_gateway
            .ingestion_gateway
        )

        document = ingestion.approved_documents.get(document_id)

        if document is None:
            self.event_recorder.record(
                event_type="RETRIEVAL_DECISION",
                outcome="DENIED",
                reason="DOCUMENT_NOT_AVAILABLE",
            )

            return SecureRAGResult(
                False, "DOCUMENT_NOT_AVAILABLE", None, 0
            )

        self.event_recorder.record(
            event_type="RETRIEVAL_DECISION",
            outcome="ALLOWED",
            reason="RETRIEVAL_AUTHORIZED",
        )

        result = generate_protected_response(
            messages=context.messages,
            classification=document.classification,
        )

        if not result.allowed:
            outcome = "ERROR" if result.reason == (
                "MODEL_GENERATION_FAILED"
            ) else "DENIED"
        elif result.redactions:
            outcome = "REDACTED"
        else:
            outcome = "ALLOWED"

        self.event_recorder.record(
            event_type="OUTPUT_PROTECTION_DECISION",
            outcome=outcome,
            reason=result.reason,
        )

        return SecureRAGResult(
            result.allowed,
            result.reason,
            result.content,
            result.redactions,
        )