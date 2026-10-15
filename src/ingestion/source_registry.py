"""Trusted source authorization for synthetic document ingestion."""

from dataclasses import dataclass


@dataclass(frozen=True)
class TrustedSource:
    source_id: str
    allowed_classifications: frozenset[str]
    active: bool = True


TRUSTED_SOURCES = {
    "SOURCE-PUBLIC": TrustedSource(
        source_id="SOURCE-PUBLIC",
        allowed_classifications=frozenset({"PUBLIC"}),
    ),
    "SOURCE-RESEARCH": TrustedSource(
        source_id="SOURCE-RESEARCH",
        allowed_classifications=frozenset(
            {"PUBLIC", "INTERNAL", "CONFIDENTIAL"}
        ),
    ),
    "SOURCE-SECURITY": TrustedSource(
        source_id="SOURCE-SECURITY",
        allowed_classifications=frozenset(
            {"PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"}
        ),
    ),
}


def authorize_source(
    source_id: str,
    classification: str,
) -> tuple[bool, str]:
    """Evaluate source eligibility against the trusted registry."""

    if not isinstance(source_id, str):
        return False, "INVALID_SOURCE_ID"

    source = TRUSTED_SOURCES.get(source_id)

    if source is None:
        return False, "UNTRUSTED_SOURCE"

    if not source.active:
        return False, "INACTIVE_SOURCE"

    if classification not in source.allowed_classifications:
        return False, "SOURCE_CLASSIFICATION_DENIED"

    return True, "SOURCE_AUTHORIZED"