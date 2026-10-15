"""Synthetic document metadata and integrity validation."""

import hashlib
import re
from dataclasses import dataclass

CLASSIFICATIONS = (
    "PUBLIC",
    "INTERNAL",
    "CONFIDENTIAL",
    "RESTRICTED",
)

DOCUMENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


@dataclass(frozen=True)
class Document:
    document_id: str
    source_id: str
    classification: str
    owner: str
    sha256: str
    content: str


def calculate_sha256(content: str) -> str:
    """Calculate the SHA-256 digest of UTF-8 document content."""
    if not isinstance(content, str):
        raise TypeError("Document content must be a string.")

    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def validate_document(document: Document) -> tuple[bool, str]:
    """Validate a document's metadata and content integrity."""

    if not isinstance(document, Document):
        return False, "INVALID_DOCUMENT_TYPE"

    if not isinstance(document.document_id, str) or not DOCUMENT_ID_PATTERN.fullmatch(
        document.document_id
    ):
        return False, "INVALID_DOCUMENT_ID"

    if not isinstance(document.source_id, str) or not document.source_id.strip():
        return False, "INVALID_SOURCE_ID"

    if document.classification not in CLASSIFICATIONS:
        return False, "INVALID_CLASSIFICATION"

    if not isinstance(document.owner, str) or not document.owner.strip():
        return False, "INVALID_OWNER"

    if not isinstance(document.content, str) or not document.content.strip():
        return False, "EMPTY_DOCUMENT"

    if not isinstance(document.sha256, str):
        return False, "INVALID_DIGEST"

    expected_digest = calculate_sha256(document.content)

    if document.sha256 != expected_digest:
        return False, "INTEGRITY_FAILURE"

    return True, "VALID"