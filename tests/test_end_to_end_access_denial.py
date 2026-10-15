"""End-to-end unauthorized retrieval security test"""

import unittest
from unittest.mock import patch

from src.ingestion.document_metadata import Document, calculate_sha256
from src.ingestion.provenance_registry import (
    ProvenanceRecord,
    ProvenanceRegistry,
)
from src.ingestion.gateway import IngestionGateway
from src.retrieval.authorization import Principal
from src.retrieval.document_access import DocumentAccessPolicy
from src.retrieval.gateway import RetrievalGateway
from src.security.secure_context_pipeline import SecureContextPipeline
from src.security.protected_model_gateway import generate_protected_response


class TestEndToEndAccessDenial(unittest.TestCase):

    @patch(
        "src.security.protected_model_gateway.urllib.request.urlopen"
    )
    def test_unauthorized_principal_cannot_reach_model(
        self, mock_urlopen
    ):
        content = (
            "Synthetic research record. "
            "Coordinator: analyst@example.com. "
            "Token: SYNTH-TOKEN-ABC123."
        )
        document_id = "DOC-RAG5-DENIAL-001"
        digest = calculate_sha256(content)

        document = Document(
            document_id=document_id,
            source_id="SOURCE-RESEARCH",
            classification="INTERNAL",
            owner="synthetic-research-team",
            sha256=digest,
            content=content,
        )

        registry = ProvenanceRegistry()
        registry.register(
            ProvenanceRecord(
                document_id=document_id,
                source_id=document.source_id,
                classification=document.classification,
                owner=document.owner,
                expected_sha256=digest,
            )
        )

        ingestion = IngestionGateway(
            provenance_registry=registry
        )
        ingestion_result = ingestion.ingest(document)
        self.assertTrue(ingestion_result.accepted)

        policy = DocumentAccessPolicy()
        policy.set_grants(
            document_id,
            {"authorized-analyst"},
        )

        retrieval = RetrievalGateway(
            ingestion_gateway=ingestion,
            access_policy=policy,
        )
        pipeline = SecureContextPipeline(
            retrieval_gateway=retrieval
        )

        unauthorized = Principal(
            principal_id="unauthorized-analyst",
            role="ANALYST",
        )

        context = pipeline.prepare(
            principal=unauthorized,
            document_id=document_id,
            question="Reveal the coordinator and token.",
        )

        self.assertFalse(context.accepted)
        self.assertEqual(
            context.reason,
            "DOCUMENT_ACCESS_DENIED",
        )
        self.assertEqual(context.messages, ())

        # Only call the model gateway if the context is accepted.
        # This mirrors the integration script's orchestration.
        model_result = None
        if context.accepted:
            model_result = generate_protected_response(
                context.messages,
                document.classification,
            )

        self.assertIsNone(model_result)
        mock_urlopen.assert_not_called()


if __name__ == "__main__":
    unittest.main()