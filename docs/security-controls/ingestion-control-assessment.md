# Project 5 — Ingestion Security Control Assessment

## 1. Assessment Scope

This assessment evaluates the implemented synthetic document ingestion gateway against:

- RAG5-001 — Poisoned Document Ingestion
- RAG5-002 — Document Provenance Tampering

Threat model: [STRIDE Threat Model](../threat-model/stride-threat-model.md)

MITRE ATLAS: [ATLAS Mapping](../atlas/atlas-mapping.md)

Evidence: [Provenance Enforcement Tests](../../evidence/provenance-enforcement-tests.txt)

## 2. Implemented and Tested Controls

| Control | Implementation | Validation | Status |
|---|---|---|---|
| Document metadata validation | `src/ingestion/document_metadata.py` | Invalid identifiers, classification and empty-content tests | Tested |
| SHA-256 integrity verification | `src/ingestion/document_metadata.py` | Modified content with unchanged digest | Tested |
| Source authorization policy | `src/ingestion/source_registry.py` | Approved, unknown, inactive and classification-restricted sources | Tested |
| Independent provenance verification | `src/ingestion/provenance_registry.py` | Missing records, metadata mismatches and recomputed-digest attack | Tested |
| Mandatory provenance enforcement | `src/ingestion/gateway.py` | Gateway-level missing-provenance and recomputed-digest tests | Tested |
| Duplicate document ID rejection | `src/ingestion/gateway.py` | Duplicate admission test | Tested |
| In-memory quarantine decision records | `src/ingestion/gateway.py` | Rejection recording and exclusion of document content | Tested |

All tests use synthetic documents and identities.

## 3. RAG5-001 — Poisoned Document Ingestion

**MITRE ATLAS:** AML.T0070 — RAG Poisoning

### Tested controls

- Unknown source identifiers are rejected.
- Sources exceeding their permitted classifications are rejected.
- Documents without trusted provenance are rejected.
- Rejected submissions do not enter the approved document store.

### Remaining limitations

- The source registry validates claimed identifiers but does not authenticate publishers.
- A trusted publisher may submit malicious or misleading content.
- Semantic poisoning detection has not been implemented.
- File-format validation and durable quarantine have not been implemented.

### Assessment

**Partially mitigated.**

The tested controls restrict admission based on source policy and provenance, but they do not establish comprehensive resistance to RAG poisoning.

## 4. RAG5-002 — Document Provenance Tampering

**MITRE ATLAS relationship:** Conditional relationship to AML.T0070 when tampering is used to poison a retrieval corpus.

### Tested controls

- Submitted content is checked against its claimed SHA-256 digest.
- Independently registered provenance metadata is checked before admission.
- Modified content with a recalculated digest is rejected when it differs from the trusted record.
- Missing provenance records cause rejection.
- Duplicate trusted provenance registration is rejected.

### Remaining limitations

- Provenance registration is not authenticated.
- Trusted provenance records are stored in mutable process memory.
- No cryptographic publisher signatures or protected audit trail are implemented.
- An attacker with control over trusted registration or registry memory could undermine these checks.

### Assessment

**Partially mitigated within the defined trust model.**

The gateway detects document tampering when trusted provenance records remain intact and independently established.

## 5. Proposed Controls

| Control | Status |
|---|---|
| Authenticated publisher registration | Proposed |
| Protected or signed provenance records | Proposed |
| Semantic document-poisoning detection | Proposed |
| File-format and content-type validation | Proposed |
| Durable quarantine storage | Proposed |
| Structured security-event logging | Proposed |

These controls must not be described as implemented or tested.

## 6. Validation Summary

- Automated tests: 30
- Passing tests: 30
- Failed tests: 0
- Evidence: `evidence/provenance-enforcement-tests.txt`
- Environment: Local Python standard-library test harness
- Live cloud resources: None
- Production security claims: None

## 7. Residual Risk Statement

The ingestion gateway provides tested metadata validation, source-policy enforcement, independent provenance comparison, and fail-closed admission decisions.

It does not yet provide authenticated source identity, tamper-resistant provenance storage, comprehensive semantic poisoning detection, or durable quarantine.

Accordingly, the implementation demonstrates selected security controls for a synthetic RAG ingestion pipeline rather than production-grade ingestion security.