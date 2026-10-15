"""Security tests for independent document provenance verification"""

import unittest

from src.ingestion.document_metadata import (
    Document,
    calculate_sha256,
    validate_document,
)
from src.ingestion.provenance_registry import (
    ProvenanceRecord,
    ProvenanceRegistry,
)


class TestProvenanceRegistry(unittest.TestCase):

    def setUp(self):
        self.registry = ProvenanceRegistry()
        self.original_content = (
            "Synthetic research document approved by the publisher."
        )

        self.record = ProvenanceRecord(
            document_id="DOC-001",
            source_id="SOURCE-RESEARCH",
            classification="INTERNAL",
            owner="synthetic-research-team",
            expected_sha256=calculate_sha256(
                self.original_content
            ),
        )

        self.registry.register(self.record)

    def make_document(self, **overrides):
        fields = {
            "document_id": self.record.document_id,
            "source_id": self.record.source_id,
            "classification": self.record.classification,
            "owner": self.record.owner,
            "sha256": self.record.expected_sha256,
            "content": self.original_content,
        }

        fields.update(overrides)
        return Document(**fields)

    def test_valid_provenance(self):
        valid, reason = self.registry.verify(
            self.make_document()
        )

        self.assertTrue(valid)
        self.assertEqual(reason, "PROVENANCE_VERIFIED")

    def test_missing_provenance_record(self):
        document = self.make_document(
            document_id="DOC-UNKNOWN"
        )

        valid, reason = self.registry.verify(document)

        self.assertFalse(valid)
        self.assertEqual(reason, "PROVENANCE_NOT_FOUND")

    def test_recomputed_digest_attack(self):
        malicious_content = (
            "Synthetic research document modified by an attacker."
        )

        document = self.make_document(
            content=malicious_content,
            sha256=calculate_sha256(malicious_content),
        )

        metadata_valid, _ = validate_document(document)

        self.assertTrue(
            metadata_valid,
            "The attack must pass ordinary digest validation.",
        )

        valid, reason = self.registry.verify(document)

        self.assertFalse(valid)
        self.assertEqual(
            reason,
            "PROVENANCE_INTEGRITY_FAILURE",
        )

    def test_source_identity_mismatch(self):
        document = self.make_document(
            source_id="SOURCE-SECURITY"
        )

        valid, reason = self.registry.verify(document)

        self.assertFalse(valid)
        self.assertEqual(
            reason,
            "PROVENANCE_METADATA_MISMATCH",
        )

    def test_classification_mismatch(self):
        document = self.make_document(
            classification="PUBLIC"
        )

        valid, reason = self.registry.verify(document)

        self.assertFalse(valid)
        self.assertEqual(
            reason,
            "PROVENANCE_METADATA_MISMATCH",
        )

    def test_owner_mismatch(self):
        document = self.make_document(
            owner="synthetic-attacker"
        )

        valid, reason = self.registry.verify(document)

        self.assertFalse(valid)
        self.assertEqual(
            reason,
            "PROVENANCE_METADATA_MISMATCH",
        )

    def test_duplicate_registration_rejected(self):
        with self.assertRaises(ValueError):
            self.registry.register(self.record)

        self.assertEqual(len(self.registry.records), 1)

    def test_invalid_trusted_digest_rejected(self):
        invalid_record = ProvenanceRecord(
            document_id="DOC-002",
            source_id="SOURCE-RESEARCH",
            classification="PUBLIC",
            owner="synthetic-research-team",
            expected_sha256="invalid-digest",
        )

        with self.assertRaises(ValueError):
            self.registry.register(invalid_record)

        self.assertNotIn(
            "DOC-002",
            self.registry.records,
        )

    def test_compromised_registry_accepts_matching_tampered_content(self):
        original = self.make_document()

        malicious_content = (
            "Synthetic research data modified by an adversary."
        )

        tampered_document = self.make_document(
            content=malicious_content,
            sha256=calculate_sha256(malicious_content),
        )

        # First establish that intact provenance rejects tampering.
        valid_before, reason_before = self.registry.verify(
            tampered_document
        )

        self.assertFalse(valid_before)
        self.assertEqual(
            reason_before,
            "PROVENANCE_INTEGRITY_FAILURE",
        )

        # Simulate direct compromise of the trusted registry.
        # This is not a demonstrated remote exploit.
        self.registry.records[original.document_id] = ProvenanceRecord(
            document_id=original.document_id,
            source_id=original.source_id,
            classification=original.classification,
            owner=original.owner,
            expected_sha256=calculate_sha256(malicious_content),
        )

        valid_after, reason_after = self.registry.verify(
            tampered_document
        )

        self.assertTrue(valid_after)
        self.assertEqual(reason_after, "PROVENANCE_VERIFIED")

if __name__ == "__main__":
    unittest.main()