"""Integration tests for the secure synthetic retrieval gateway."""

import unittest

from src.ingestion.document_metadata import (
    Document,
    calculate_sha256,
)
from src.ingestion.provenance_registry import ProvenanceRecord
from src.ingestion.gateway import IngestionGateway
from src.retrieval.authorization import Principal
from src.retrieval.document_access import DocumentAccessPolicy
from src.retrieval.gateway import RetrievalGateway


class TestRetrievalGateway(unittest.TestCase):

    def setUp(self):
        self.ingestion = IngestionGateway()
        self.access_policy = DocumentAccessPolicy()
        self.gateway = RetrievalGateway(
            self.ingestion,
            self.access_policy,
        )

    def make_document(
        self,
        document_id="DOC-TEAM-A",
        classification="CONFIDENTIAL",
    ):
        content = f"Synthetic confidential content for {document_id}"

        return Document(
            document_id=document_id,
            source_id="SOURCE-RESEARCH",
            classification=classification,
            owner="synthetic-team-a",
            sha256=calculate_sha256(content),
            content=content,
        )

    def admit_document(self, document):
        record = ProvenanceRecord(
            document_id=document.document_id,
            source_id=document.source_id,
            classification=document.classification,
            owner=document.owner,
            expected_sha256=document.sha256,
        )

        self.ingestion.provenance_registry.register(record)
        result = self.ingestion.ingest(document)
        self.assertTrue(result.accepted, result.reason)

    def assert_denied_without_content(self, result):
        self.assertFalse(result.allowed)
        self.assertIsNone(result.content)
        self.assertIsNone(result.document_id)

    def test_authorized_retrieval_returns_content(self):
        document = self.make_document()
        self.admit_document(document)

        self.access_policy.set_grants(
            document.document_id,
            {"USER-ALICE"},
        )

        result = self.gateway.retrieve(
            Principal("USER-ALICE", "RESEARCHER"),
            document.document_id,
        )

        self.assertTrue(result.allowed)
        self.assertEqual(result.reason, "RETRIEVAL_AUTHORIZED")
        self.assertEqual(result.document_id, document.document_id)
        self.assertEqual(result.content, document.content)

    def test_cross_team_retrieval_denied(self):
        team_a = self.make_document("DOC-TEAM-A")
        team_b = self.make_document("DOC-TEAM-B")

        self.admit_document(team_a)
        self.admit_document(team_b)

        self.access_policy.set_grants(
            team_a.document_id,
            {"USER-ALICE"},
        )
        self.access_policy.set_grants(
            team_b.document_id,
            {"USER-BOB"},
        )

        result = self.gateway.retrieve(
            Principal("USER-ALICE", "RESEARCHER"),
            team_b.document_id,
        )

        self.assert_denied_without_content(result)
        self.assertEqual(result.reason, "DOCUMENT_ACCESS_DENIED")

    def test_classification_denial_overrides_grant(self):
        document = self.make_document()
        self.admit_document(document)

        self.access_policy.set_grants(
            document.document_id,
            {"USER-ANALYST"},
        )

        result = self.gateway.retrieve(
            Principal("USER-ANALYST", "ANALYST"),
            document.document_id,
        )

        self.assert_denied_without_content(result)
        self.assertEqual(result.reason, "RETRIEVAL_DENIED")

    def test_missing_document_grants_denied(self):
        document = self.make_document()
        self.admit_document(document)

        result = self.gateway.retrieve(
            Principal("USER-ALICE", "RESEARCHER"),
            document.document_id,
        )

        self.assert_denied_without_content(result)
        self.assertEqual(
            result.reason,
            "DOCUMENT_GRANTS_NOT_FOUND",
        )

    def test_unknown_document_denied(self):
        result = self.gateway.retrieve(
            Principal("USER-ALICE", "RESEARCHER"),
            "DOC-NOT-FOUND",
        )

        self.assert_denied_without_content(result)
        self.assertEqual(
            result.reason,
            "DOCUMENT_NOT_AVAILABLE",
        )

    def test_invalid_document_id_denied(self):
        result = self.gateway.retrieve(
            Principal("USER-ALICE", "RESEARCHER"),
            "",
        )

        self.assert_denied_without_content(result)
        self.assertEqual(result.reason, "INVALID_DOCUMENT_ID")

    def test_unknown_role_denied(self):
        document = self.make_document()
        self.admit_document(document)

        self.access_policy.set_grants(
            document.document_id,
            {"USER-ALICE"},
        )

        result = self.gateway.retrieve(
            Principal("USER-ALICE", "SUPERUSER"),
            document.document_id,
        )

        self.assert_denied_without_content(result)
        self.assertEqual(result.reason, "UNKNOWN_ROLE")

    def test_rejected_ingestion_not_retrievable(self):
        document = self.make_document("DOC-UNTRUSTED")

        ingestion_result = self.ingestion.ingest(document)
        self.assertFalse(ingestion_result.accepted)

        self.access_policy.set_grants(
            document.document_id,
            {"USER-ALICE"},
        )

        result = self.gateway.retrieve(
            Principal("USER-ALICE", "RESEARCHER"),
            document.document_id,
        )

        self.assert_denied_without_content(result)
        self.assertEqual(
            result.reason,
            "DOCUMENT_NOT_AVAILABLE",
        )


if __name__ == "__main__":
    unittest.main()