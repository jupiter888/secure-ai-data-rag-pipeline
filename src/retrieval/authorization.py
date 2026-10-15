"""Deny-by-default retrieval authorization for synthetic identities."""

from dataclasses import dataclass

from src.ingestion.document_metadata import Document


ROLE_PERMISSIONS = {
    "GUEST": frozenset({"PUBLIC"}),
    "ANALYST": frozenset({"PUBLIC", "INTERNAL"}),
    "RESEARCHER": frozenset(
        {"PUBLIC", "INTERNAL", "CONFIDENTIAL"}
    ),
    "SECURITY_ADMIN": frozenset(
        {"PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"}
    ),
}


@dataclass(frozen=True)
class Principal:
    principal_id: str
    role: str


def authorize_retrieval(
    principal: Principal,
    document: Document,
) -> tuple[bool, str]:
    """Authorize access using an explicit role/classification policy."""

    if not isinstance(principal, Principal):
        return False, "INVALID_PRINCIPAL"

    if (
        not isinstance(principal.principal_id, str)
        or not principal.principal_id.strip()
    ):
        return False, "INVALID_PRINCIPAL_ID"

    if not isinstance(principal.role, str):
        return False, "INVALID_ROLE"

    permissions = ROLE_PERMISSIONS.get(principal.role)

    if permissions is None:
        return False, "UNKNOWN_ROLE"

    if not isinstance(document, Document):
        return False, "INVALID_DOCUMENT"

    if document.classification not in permissions:
        return False, "RETRIEVAL_DENIED"

    return True, "RETRIEVAL_AUTHORIZED"