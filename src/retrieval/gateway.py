"""Fail-closed retrieval gateway for approved synthetic documents."""

from dataclasses import dataclass

from src.ingestion.gateway import IngestionGateway
from src.retrieval.authorization import Principal
from src.retrieval.document_access import DocumentAccessPolicy


@dataclass(frozen=True)
class RetrievalResult:
    allowed: bool
    reason: str
    document_id: str | None
    content: str | None


@dataclass
class RetrievalGateway:
    ingestion_gateway: IngestionGateway
    access_policy: DocumentAccessPolicy

    def retrieve(
        self,
        principal: Principal,
        document_id: str,
    ) -> RetrievalResult:
        """Retrieve content only after both authorization checks pass."""

        if not isinstance(document_id, str) or not document_id:
            return RetrievalResult(
                False, "INVALID_DOCUMENT_ID", None, None
            )

        document = self.ingestion_gateway.approved_documents.get(
            document_id
        )

        if document is None:
            return RetrievalResult(
                False, "DOCUMENT_NOT_AVAILABLE", None, None
            )

        allowed, reason = self.access_policy.authorize(
            principal, document
        )

        if not allowed:
            return RetrievalResult(
                False, reason, None, None
            )

        return RetrievalResult(
            True,
            "RETRIEVAL_AUTHORIZED",
            document.document_id,
            document.content,
        )