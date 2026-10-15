"""Security tests for synthetic document metadata validation."""

import unittest

from src.ingestion.document_metadata import (
    Document,
    calculate_sha256,
    validate_document,
)


class TestDocumentMetadata(unittest.TestCase):

    def make_document(self, **overrides):
        content = "Synthetic public research document."

        fields = {
            "document_id": "DOC-001",
            "source_id": "SOURCE-001",
            "classification": "PUBLIC",
            "owner": "synthetic-research-team",
            "sha256": calculate_sha256(content),
            "content": content,
        }

        fields.update(overrides)
        return Document(**fields)

    def test_valid_document(self):
        document = self.make_document()

        valid, reason = validate_document(document)

        self.assertTrue(valid)
        self.assertEqual(reason, "VALID")

    def test_invalid_classification(self):
        document = self.make_document(
            classification="TOP_SECRET"
        )

        valid, reason = validate_document(document)

        self.assertFalse(valid)
        self.assertEqual(reason, "INVALID_CLASSIFICATION")

    def test_content_tampering(self):
        document = self.make_document(
            content="Unauthorized modified document content."
        )

        valid, reason = validate_document(document)

        self.assertFalse(valid)
        self.assertEqual(reason, "INTEGRITY_FAILURE")

    def test_missing_source_identifier(self):
        document = self.make_document(
            source_id=""
        )

        valid, reason = validate_document(document)

        self.assertFalse(valid)
        self.assertEqual(reason, "INVALID_SOURCE_ID")

    def test_empty_document(self):
        document = self.make_document(
            content=""
        )

        valid, reason = validate_document(document)

        self.assertFalse(valid)
        self.assertEqual(reason, "EMPTY_DOCUMENT")


if __name__ == "__main__":
    unittest.main()