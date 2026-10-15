"""Authorized retrieval-to-context pipeline for synthetic RAG."""

from dataclasses import dataclass

from src.retrieval.authorization import Principal
from src.retrieval.gateway import RetrievalGateway
from src.security.context_builder import build_rag_context


@dataclass(frozen=True)
class SecureContextResult:
    accepted: bool
    reason: str
    messages: tuple[dict[str, str], ...]


@dataclass
class SecureContextPipeline:
    retrieval_gateway: RetrievalGateway

    def prepare(
        self,
        principal: Principal,
        document_id: str,
        question: str,
    ) -> SecureContextResult:
        """Authorize retrieval, screen content, and construct context."""

        # Validate the question before requesting document content.
        if not isinstance(question, str) or not question.strip():
            return SecureContextResult(
                False, "INVALID_QUESTION", ()
            )

        retrieval = self.retrieval_gateway.retrieve(
            principal,
            document_id,
        )

        if not retrieval.allowed:
            return SecureContextResult(
                False, retrieval.reason, ()
            )

        if retrieval.document_id is None:
            return SecureContextResult(
                False, "INVALID_RETRIEVAL_RESULT", ()
            )

        context = build_rag_context(
            question=question,
            document_id=retrieval.document_id,
            retrieved_content=retrieval.content,
        )

        if not context.accepted:
            return SecureContextResult(
                False, context.reason, ()
            )

        return SecureContextResult(
            True,
            "SECURE_CONTEXT_PREPARED",
            context.messages,
        )