"""Security tests for synthetic document source authorization."""

import unittest
from unittest.mock import patch

from src.ingestion.source_registry import (
    TrustedSource,
    authorize_source,
)


class TestSourceRegistry(unittest.TestCase):

    def test_public_source_allowed_public(self):
        allowed, reason = authorize_source(
            "SOURCE-PUBLIC", "PUBLIC"
        )
        self.assertTrue(allowed)
        self.assertEqual(reason, "SOURCE_AUTHORIZED")

    def test_public_source_denied_confidential(self):
        allowed, reason = authorize_source(
            "SOURCE-PUBLIC", "CONFIDENTIAL"
        )
        self.assertFalse(allowed)
        self.assertEqual(reason, "SOURCE_CLASSIFICATION_DENIED")

    def test_research_source_allowed_confidential(self):
        allowed, reason = authorize_source(
            "SOURCE-RESEARCH", "CONFIDENTIAL"
        )
        self.assertTrue(allowed)
        self.assertEqual(reason, "SOURCE_AUTHORIZED")

    def test_research_source_denied_restricted(self):
        allowed, reason = authorize_source(
            "SOURCE-RESEARCH", "RESTRICTED"
        )
        self.assertFalse(allowed)
        self.assertEqual(reason, "SOURCE_CLASSIFICATION_DENIED")

    def test_security_source_allowed_restricted(self):
        allowed, reason = authorize_source(
            "SOURCE-SECURITY", "RESTRICTED"
        )
        self.assertTrue(allowed)
        self.assertEqual(reason, "SOURCE_AUTHORIZED")

    def test_unknown_source_denied(self):
        allowed, reason = authorize_source(
            "SOURCE-ATTACKER", "PUBLIC"
        )
        self.assertFalse(allowed)
        self.assertEqual(reason, "UNTRUSTED_SOURCE")

    def test_invalid_source_type_denied(self):
        allowed, reason = authorize_source(
            None, "PUBLIC"
        )
        self.assertFalse(allowed)
        self.assertEqual(reason, "INVALID_SOURCE_ID")

    def test_inactive_source_denied(self):
        inactive_source = TrustedSource(
            source_id="SOURCE-DISABLED",
            allowed_classifications=frozenset({"PUBLIC"}),
            active=False,
        )

        with patch.dict(
            "src.ingestion.source_registry.TRUSTED_SOURCES",
            {"SOURCE-DISABLED": inactive_source},
        ):
            allowed, reason = authorize_source(
                "SOURCE-DISABLED", "PUBLIC"
            )

        self.assertFalse(allowed)
        self.assertEqual(reason, "INACTIVE_SOURCE")


if __name__ == "__main__":
    unittest.main()