"""Independent provenance records for synthetic document ingestion."""

import re
from dataclasses import dataclass, field

from src.ingestion.document_metadata import (
    Document,
    calculate_sha256,
)

SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class ProvenanceRecord:
    document_id: str
    source_id: str
    classification: str
    owner: str
    expected_sha256: str


@dataclass
class ProvenanceRegistry:
    """Trusted records registered outside the document submission path."""

    records: dict[str, ProvenanceRecord] = field(
        default_factory=dict
    )

    def register(self, record: ProvenanceRecord) -> None:
        """Register a trusted record through the administrative interface."""

        if not isinstance(record, ProvenanceRecord):
            raise TypeError("Invalid provenance record.")

        if (
            not isinstance(record.document_id, str)
            or not record.document_id
        ):
            raise ValueError("Invalid document identifier.")

        if (
            not isinstance(record.expected_sha256, str)
            or not SHA256_PATTERN.fullmatch(record.expected_sha256)
        ):
            raise ValueError("Invalid SHA-256 digest.")

        if record.document_id in self.records:
            raise ValueError("Provenance record already exists.")

        self.records[record.document_id] = record

    def verify(self, document: Document) -> tuple[bool, str]:
        """Compare a submission against independently stored metadata."""

        if not isinstance(document, Document):
            return False, "INVALID_DOCUMENT_TYPE"

        record = self.records.get(document.document_id)

        if record is None:
            return False, "PROVENANCE_NOT_FOUND"

        if (
            document.source_id != record.source_id
            or document.classification != record.classification
            or document.owner != record.owner
        ):
            return False, "PROVENANCE_METADATA_MISMATCH"

        actual_digest = calculate_sha256(document.content)

        if actual_digest != record.expected_sha256:
            return False, "PROVENANCE_INTEGRITY_FAILURE"

        return True, "PROVENANCE_VERIFIED"