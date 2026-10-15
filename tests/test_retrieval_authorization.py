"""Security tests for synthetic retrieval authorization."""

import unittest

from src.ingestion.document_metadata import (
    Document,
    calculate_sha256,
)
from src.retrieval.authorization import (
    Principal,
    authorize_retrieval,
)


class TestRetrievalAuthorization(unittest.TestCase):

    def make_document(self, classification="PUBLIC"):
        content = "Synthetic document for retrieval security tests."

        return Document(
            document_id="DOC-RETRIEVAL-001",
            source_id="SOURCE-RESEARCH",
            classification=classification,
            owner="synthetic-research-team",
            sha256=calculate_sha256(content),
            content=content,
        )

    def test_guest_allowed_public(self):
        principal = Principal("USER-GUEST", "GUEST")
        document = self.make_document("PUBLIC")

        allowed, reason = authorize_retrieval(principal, document)

        self.assertTrue(allowed)
        self.assertEqual(reason, "RETRIEVAL_AUTHORIZED")

    def test_guest_denied_internal(self):
        principal = Principal("USER-GUEST", "GUEST")
        document = self.make_document("INTERNAL")

        allowed, reason = authorize_retrieval(principal, document)

        self.assertFalse(allowed)
        self.assertEqual(reason, "RETRIEVAL_DENIED")

    def test_analyst_allowed_internal(self):
        principal = Principal("USER-ANALYST", "ANALYST")
        document = self.make_document("INTERNAL")

        allowed, reason = authorize_retrieval(principal, document)

        self.assertTrue(allowed)
        self.assertEqual(reason, "RETRIEVAL_AUTHORIZED")

    def test_analyst_denied_confidential(self):
        principal = Principal("USER-ANALYST", "ANALYST")
        document = self.make_document("CONFIDENTIAL")

        allowed, reason = authorize_retrieval(principal, document)

        self.assertFalse(allowed)
        self.assertEqual(reason, "RETRIEVAL_DENIED")

    def test_researcher_allowed_confidential(self):
        principal = Principal("USER-RESEARCHER", "RESEARCHER")
        document = self.make_document("CONFIDENTIAL")

        allowed, reason = authorize_retrieval(principal, document)

        self.assertTrue(allowed)
        self.assertEqual(reason, "RETRIEVAL_AUTHORIZED")

    def test_researcher_denied_restricted(self):
        principal = Principal("USER-RESEARCHER", "RESEARCHER")
        document = self.make_document("RESTRICTED")

        allowed, reason = authorize_retrieval(principal, document)

        self.assertFalse(allowed)
        self.assertEqual(reason, "RETRIEVAL_DENIED")

    def test_security_admin_allowed_restricted(self):
        principal = Principal("USER-ADMIN", "SECURITY_ADMIN")
        document = self.make_document("RESTRICTED")

        allowed, reason = authorize_retrieval(principal, document)

        self.assertTrue(allowed)
        self.assertEqual(reason, "RETRIEVAL_AUTHORIZED")

    def test_unknown_role_denied(self):
        principal = Principal("USER-ATTACKER", "SUPERUSER")
        document = self.make_document()

        allowed, reason = authorize_retrieval(principal, document)

        self.assertFalse(allowed)
        self.assertEqual(reason, "UNKNOWN_ROLE")

    def test_invalid_principal_denied(self):
        document = self.make_document()

        allowed, reason = authorize_retrieval(None, document)

        self.assertFalse(allowed)
        self.assertEqual(reason, "INVALID_PRINCIPAL")

    def test_empty_principal_id_denied(self):
        principal = Principal("", "SECURITY_ADMIN")
        document = self.make_document()

        allowed, reason = authorize_retrieval(principal, document)

        self.assertFalse(allowed)
        self.assertEqual(reason, "INVALID_PRINCIPAL_ID")

    def test_invalid_role_type_denied(self):
        principal = Principal("USER-001", None)
        document = self.make_document()

        allowed, reason = authorize_retrieval(principal, document)

        self.assertFalse(allowed)
        self.assertEqual(reason, "INVALID_ROLE")

    def test_invalid_document_denied(self):
        principal = Principal("USER-ADMIN", "SECURITY_ADMIN")

        allowed, reason = authorize_retrieval(principal, None)

        self.assertFalse(allowed)
        self.assertEqual(reason, "INVALID_DOCUMENT")


if __name__ == "__main__":
    unittest.main()