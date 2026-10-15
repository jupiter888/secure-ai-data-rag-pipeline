"""Fail-closed synthetic document ingestion gateway."""

from dataclasses import dataclass, field

from src.ingestion.document_metadata import (
    Document,
    validate_document,
)
from src.ingestion.source_registry import authorize_source
from src.ingestion.provenance_registry import ProvenanceRegistry


@dataclass(frozen=True)
class IngestionResult:
    accepted: bool
    reason: str
    document_id: str | None


@dataclass
class IngestionGateway:
    provenance_registry: ProvenanceRegistry = field(
        default_factory=ProvenanceRegistry
    )
    approved_documents: dict[str, Document] = field(
        default_factory=dict
    )
    quarantine: list[dict[str, str | None]] = field(
        default_factory=list
    )

    def ingest(self, document: Document) -> IngestionResult:
        """Validate, authorize, and verify provenance before admission."""

        document_id = (
            document.document_id
            if isinstance(document, Document)
            and isinstance(document.document_id, str)
            else None
        )

        valid, reason = validate_document(document)

        if not valid:
            return self._reject(document_id, reason)

        authorized, reason = authorize_source(
            document.source_id,
            document.classification,
        )

        if not authorized:
            return self._reject(document_id, reason)

        provenance_valid, reason = self.provenance_registry.verify(
            document
        )

        if not provenance_valid:
            return self._reject(document_id, reason)

        if document.document_id in self.approved_documents:
            return self._reject(
                document_id,
                "DUPLICATE_DOCUMENT_ID",
            )

        self.approved_documents[document.document_id] = document

        return IngestionResult(
            accepted=True,
            reason="DOCUMENT_ACCEPTED",
            document_id=document.document_id,
        )

    def _reject(
        self,
        document_id: str | None,
        reason: str,
    ) -> IngestionResult:
        """Record a rejection without retaining submitted content."""

        self.quarantine.append(
            {
                "document_id": document_id,
                "reason": reason,
            }
        )

        return IngestionResult(
            accepted=False,
            reason=reason,
            document_id=document_id,
        )