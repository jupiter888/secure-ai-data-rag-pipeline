"""Security tests for document-specific RAG authorization."""

import unittest

from src.ingestion.document_metadata import (
    Document,
    calculate_sha256,
)
from src.retrieval.authorization import Principal
from src.retrieval.document_access import DocumentAccessPolicy


class TestDocumentAccessPolicy(unittest.TestCase):

    def setUp(self):
        self.policy = DocumentAccessPolicy()

    def make_document(
        self,
        document_id="DOC-TEAM-A",
        classification="CONFIDENTIAL",
    ):
        content = "Synthetic research document."

        return Document(
            document_id=document_id,
            source_id="SOURCE-RESEARCH",
            classification=classification,
            owner="synthetic-team-a",
            sha256=calculate_sha256(content),
            content=content,
        )

    def test_authorized_researcher_allowed(self):
        document = self.make_document()
        principal = Principal("USER-ALICE", "RESEARCHER")

        self.policy.set_grants(
            document.document_id,
            {"USER-ALICE"},
        )

        allowed, reason = self.policy.authorize(
            principal, document
        )

        self.assertTrue(allowed)
        self.assertEqual(
            reason, "DOCUMENT_ACCESS_AUTHORIZED"
        )

    def test_researcher_without_grant_denied(self):
        document = self.make_document()
        principal = Principal("USER-BOB", "RESEARCHER")

        self.policy.set_grants(
            document.document_id,
            {"USER-ALICE"},
        )

        allowed, reason = self.policy.authorize(
            principal, document
        )

        self.assertFalse(allowed)
        self.assertEqual(
            reason, "DOCUMENT_ACCESS_DENIED"
        )

    def test_cross_team_document_access_denied(self):
        team_a = self.make_document("DOC-TEAM-A")
        team_b = self.make_document("DOC-TEAM-B")

        self.policy.set_grants(
            team_a.document_id,
            {"USER-ALICE"},
        )
        self.policy.set_grants(
            team_b.document_id,
            {"USER-BOB"},
        )

        principal = Principal("USER-ALICE", "RESEARCHER")

        allowed_a, _ = self.policy.authorize(
            principal, team_a
        )
        allowed_b, reason_b = self.policy.authorize(
            principal, team_b
        )

        self.assertTrue(allowed_a)
        self.assertFalse(allowed_b)
        self.assertEqual(
            reason_b, "DOCUMENT_ACCESS_DENIED"
        )

    def test_role_denial_overrides_document_grant(self):
        document = self.make_document(
            classification="CONFIDENTIAL"
        )
        principal = Principal("USER-ANALYST", "ANALYST")

        self.policy.set_grants(
            document.document_id,
            {"USER-ANALYST"},
        )

        allowed, reason = self.policy.authorize(
            principal, document
        )

        self.assertFalse(allowed)
        self.assertEqual(reason, "RETRIEVAL_DENIED")

    def test_missing_grants_denied(self):
        document = self.make_document()
        principal = Principal("USER-ALICE", "RESEARCHER")

        allowed, reason = self.policy.authorize(
            principal, document
        )

        self.assertFalse(allowed)
        self.assertEqual(
            reason, "DOCUMENT_GRANTS_NOT_FOUND"
        )

    def test_unknown_role_denied_despite_grant(self):
        document = self.make_document()
        principal = Principal("USER-ALICE", "SUPERUSER")

        self.policy.set_grants(
            document.document_id,
            {"USER-ALICE"},
        )

        allowed, reason = self.policy.authorize(
            principal, document
        )

        self.assertFalse(allowed)
        self.assertEqual(reason, "UNKNOWN_ROLE")

    def test_empty_grants_deny_access(self):
        document = self.make_document()
        principal = Principal("USER-ALICE", "RESEARCHER")

        self.policy.set_grants(document.document_id, set())

        allowed, reason = self.policy.authorize(
            principal, document
        )

        self.assertFalse(allowed)
        self.assertEqual(
            reason, "DOCUMENT_ACCESS_DENIED"
        )

    def test_invalid_grant_collection_rejected(self):
        with self.assertRaises(TypeError):
            self.policy.set_grants(
                "DOC-TEAM-A", ["USER-ALICE"]
            )

    def test_invalid_principal_grant_rejected(self):
        with self.assertRaises(ValueError):
            self.policy.set_grants(
                "DOC-TEAM-A", {""}
            )

    def test_invalid_document_id_rejected(self):
        with self.assertRaises(ValueError):
            self.policy.set_grants("", {"USER-ALICE"})


if __name__ == "__main__":
    unittest.main()