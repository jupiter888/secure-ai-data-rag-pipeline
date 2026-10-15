"""Offline tests for structured security-event recording"""

import unittest
from dataclasses import fields
from datetime import datetime

from src.security.security_events import (
    SecurityEvent,
    SecurityEventRecorder,
)


class TestSecurityEvents(unittest.TestCase):

    def setUp(self):
        self.recorder = SecurityEventRecorder()

    def test_valid_denial_recorded(self):
        event = self.recorder.record(
            event_type="RETRIEVAL_DECISION",
            outcome="DENIED",
            reason="DOCUMENT_ACCESS_DENIED",
            document_id="DOC-001",
        )

        self.assertEqual(event.outcome, "DENIED")
        self.assertEqual(event.reason, "DOCUMENT_ACCESS_DENIED")
        self.assertEqual(event.document_id, "DOC-001")
        self.assertEqual(len(self.recorder.events), 1)

    def test_redaction_event_recorded(self):
        event = self.recorder.record(
            event_type="OUTPUT_PROTECTION_DECISION",
            outcome="REDACTED",
            reason="OUTPUT_REDACTED",
        )

        self.assertEqual(event.outcome, "REDACTED")
        self.assertIsNone(event.document_id)

    def test_timestamp_is_timezone_aware(self):
        event = self.recorder.record(
            "INGESTION_DECISION",
            "ALLOWED",
            "DOCUMENT_ACCEPTED",
        )

        timestamp = datetime.fromisoformat(event.timestamp)
        self.assertIsNotNone(timestamp.tzinfo)
        self.assertIsNotNone(timestamp.utcoffset())

    def test_unknown_event_type_rejected(self):
        with self.assertRaises(ValueError):
            self.recorder.record(
                "UNKNOWN_EVENT",
                "DENIED",
                "ACCESS_DENIED",
            )

        self.assertEqual(self.recorder.events, [])

    def test_unknown_outcome_rejected(self):
        with self.assertRaises(ValueError):
            self.recorder.record(
                "RETRIEVAL_DECISION",
                "SUCCESS",
                "RETRIEVAL_AUTHORIZED",
            )

        self.assertEqual(self.recorder.events, [])

    def test_sensitive_reason_text_rejected(self):
        with self.assertRaises(ValueError):
            self.recorder.record(
                "RETRIEVAL_DECISION",
                "DENIED",
                "Email analyst@example.com",
            )

        self.assertEqual(self.recorder.events, [])

    def test_invalid_document_identifier_rejected(self):
        with self.assertRaises(ValueError):
            self.recorder.record(
                "RETRIEVAL_DECISION",
                "DENIED",
                "DOCUMENT_ACCESS_DENIED",
                "DOC/../../private",
            )

        self.assertEqual(self.recorder.events, [])

    def test_event_schema_contains_metadata_only(self):
        names = {field.name for field in fields(SecurityEvent)}

        self.assertEqual(
            names,
            {
                "timestamp",
                "event_type",
                "outcome",
                "reason",
                "document_id",
            },
        )

    def test_multiple_events_preserve_order(self):
        self.recorder.record(
            "RETRIEVAL_DECISION",
            "ALLOWED",
            "RETRIEVAL_AUTHORIZED",
        )
        self.recorder.record(
            "OUTPUT_PROTECTION_DECISION",
            "REDACTED",
            "OUTPUT_REDACTED",
        )

        self.assertEqual(len(self.recorder.events), 2)
        self.assertEqual(
            self.recorder.events[0].event_type,
            "RETRIEVAL_DECISION",
        )
        self.assertEqual(
            self.recorder.events[1].event_type,
            "OUTPUT_PROTECTION_DECISION",
        )


if __name__ == "__main__":
    unittest.main()