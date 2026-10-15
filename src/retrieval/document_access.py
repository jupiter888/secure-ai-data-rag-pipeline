"""Document-specific authorization for synthetic RAG retrieval."""

from dataclasses import dataclass, field

from src.ingestion.document_metadata import Document
from src.retrieval.authorization import (
    Principal,
    authorize_retrieval,
)


@dataclass
class DocumentAccessPolicy:
    """Explicit per-document principal grants."""

    grants: dict[str, frozenset[str]] = field(
        default_factory=dict
    )

    def set_grants(
        self,
        document_id: str,
        principal_ids: set[str],
    ) -> None:
        """Configure grants through a trusted administrative interface."""

        if not isinstance(document_id, str) or not document_id:
            raise ValueError("Invalid document identifier.")

        if not isinstance(principal_ids, set):
            raise TypeError("Principal grants must be a set.")

        if not all(
            isinstance(value, str) and bool(value.strip())
            for value in principal_ids
        ):
            raise ValueError("Invalid principal identifier.")

        self.grants[document_id] = frozenset(principal_ids)

    def authorize(
        self,
        principal: Principal,
        document: Document,
    ) -> tuple[bool, str]:
        """Require both role permission and document-specific access."""

        role_allowed, reason = authorize_retrieval(
            principal,
            document,
        )

        if not role_allowed:
            return False, reason

        allowed_principals = self.grants.get(
            document.document_id
        )

        if allowed_principals is None:
            return False, "DOCUMENT_GRANTS_NOT_FOUND"

        if principal.principal_id not in allowed_principals:
            return False, "DOCUMENT_ACCESS_DENIED"

        return True, "DOCUMENT_ACCESS_AUTHORIZED"