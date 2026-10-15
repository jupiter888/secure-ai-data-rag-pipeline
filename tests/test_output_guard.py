"""Unit tests for synthetic RAG output protection"""

import unittest

from src.security.output_guard import protect_output


class TestOutputGuard(unittest.TestCase):

    def test_clean_public_output_approved(self):
        result = protect_output(
            "The approved retention period is 30 days.",
            "PUBLIC",
        )

        self.assertTrue(result.allowed)
        self.assertEqual(result.reason, "OUTPUT_APPROVED")
        self.assertEqual(result.redactions, 0)
        self.assertEqual(
            result.content,
            "The approved retention period is 30 days.",
        )

    def test_synthetic_email_redacted(self):
        result = protect_output(
            "Contact analyst@example.com for assistance.",
            "INTERNAL",
        )

        self.assertTrue(result.allowed)
        self.assertEqual(result.reason, "OUTPUT_REDACTED")
        self.assertEqual(result.redactions, 1)
        self.assertEqual(
            result.content,
            "Contact [REDACTED_EMAIL] for assistance.",
        )

    def test_synthetic_token_redacted(self):
        result = protect_output(
            "Token: SYNTH-TOKEN-ABC123",
            "CONFIDENTIAL",
        )

        self.assertTrue(result.allowed)
        self.assertEqual(result.redactions, 1)
        self.assertNotIn("SYNTH-TOKEN-ABC123", result.content)

    def test_multiple_sensitive_values_redacted(self):
        result = protect_output(
            "Email: analyst@example.com; "
            "Token: SYNTH-TOKEN-ABC123",
            "INTERNAL",
        )

        self.assertTrue(result.allowed)
        self.assertEqual(result.redactions, 2)
        self.assertNotIn("analyst@example.com", result.content)
        self.assertNotIn("SYNTH-TOKEN-ABC123", result.content)

    def test_restricted_output_blocked(self):
        result = protect_output(
            "Synthetic restricted research material.",
            "RESTRICTED",
        )

        self.assertFalse(result.allowed)
        self.assertEqual(
            result.reason,
            "RESTRICTED_OUTPUT_BLOCKED",
        )
        self.assertIsNone(result.content)

    def test_unknown_classification_rejected(self):
        result = protect_output(
            "Synthetic policy information.",
            "UNKNOWN",
        )

        self.assertFalse(result.allowed)
        self.assertEqual(
            result.reason,
            "INVALID_CLASSIFICATION",
        )
        self.assertIsNone(result.content)

    def test_empty_output_rejected(self):
        result = protect_output("", "PUBLIC")

        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "INVALID_OUTPUT")
        self.assertIsNone(result.content)

    def test_invalid_output_type_rejected(self):
        result = protect_output(None, "PUBLIC")

        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "INVALID_OUTPUT")
        self.assertIsNone(result.content)

    def test_confidential_clean_output_approved(self):
        result = protect_output(
            "Synthetic research summary.",
            "CONFIDENTIAL",
        )

        self.assertTrue(result.allowed)
        self.assertEqual(result.reason, "OUTPUT_APPROVED")
        self.assertEqual(
            result.content,
            "Synthetic research summary.",
        )

    def test_restricted_token_not_released(self):
        result = protect_output(
            "SYNTH-TOKEN-SECRET123",
            "RESTRICTED",
        )

        self.assertFalse(result.allowed)
        self.assertIsNone(result.content)
        self.assertEqual(result.redactions, 0)


if __name__ == "__main__":
    unittest.main()