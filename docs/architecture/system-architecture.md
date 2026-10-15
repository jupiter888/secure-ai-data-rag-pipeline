# Project 5 — Secure AI Data and RAG Pipeline

## 1. System Overview

This project implements a synthetic, offline retrieval-augmented generation (RAG) pipeline designed to demonstrate secure document ingestion, provenance validation, data classification, retrieval authorization, prompt-injection resistance, sensitive-data protection, and security monitoring.

The project extends the security concepts demonstrated in Project 3 without relying on its original files or infrastructure.

## 2. System Components

1. **Document Sources:** Synthetic documents assigned source identities, classification levels, ownership metadata, and integrity hashes.
2. **Ingestion Gateway:** Validates document format, source authorization, metadata, content integrity, and classification before admission.
3. **Quarantine:** Isolates rejected or suspicious documents and records the reason for rejection.
4. **Document Store:** Maintains approved document content and security metadata.
5. **Identity and Authorization Service:** Determines whether a requesting principal may retrieve a particular document.
6. **Retrieval Service:** Applies authorization filtering before returning content to the RAG pipeline.
7. **LLM Interface:** Processes authorized retrieved content while treating document text as untrusted data.
8. **Output Security Controls:** Validate generated responses for unauthorized disclosure and policy violations.
9. **Security Event Logger:** Records ingestion decisions, authorization failures, suspicious retrievals, and output-control results.

## 3. Trust Boundaries

### TB-01 — Document Source to Ingestion Gateway

External document content and source metadata are untrusted until validated.

### TB-02 — Ingestion Gateway to Approved Document Store

Only documents satisfying ingestion and provenance requirements may cross into approved storage.

### TB-03 — User Identity to Retrieval Service

Requests must be associated with a recognized synthetic identity and evaluated against document-level authorization rules.

### TB-04 — Retrieved Content to LLM

Retrieved documents are untrusted context, not authoritative instructions. Embedded instructions must not override system security requirements.

### TB-05 — LLM Output to User

Generated responses must pass output security checks before being returned to the requesting principal.

## 4. Data Classification

The lab uses four synthetic classifications:

- Public
- Internal
- Confidential
- Restricted

Access decisions must use explicit authorization rules rather than assuming that classification alone establishes permission.

## 5. Security Requirements

- Reject unauthorized or malformed ingestion requests.
- Verify document provenance and content integrity.
- Quarantine suspicious or rejected documents.
- Enforce document-level authorization before retrieval.
- Prevent retrieved content from overriding trusted instructions.
- Prevent unauthorized disclosure of sensitive document content.
- Record security-relevant events without exposing protected content.
- Maintain reproducible adversarial tests and regression evidence.

## 6. Threat Modeling

The project uses STRIDE to identify trust-boundary threats and MITRE ATLAS to map applicable AI-specific attack techniques.

Each ATLAS mapping must include a verified technique identifier, prerequisites, tested controls, evidence references, and residual risk.

Controls must be classified as Proposed, Implemented, or Tested.

## 7. Implementation Constraints

- Synthetic documents and identities only.
- Offline-first execution.
- No production credentials or confidential enterprise data.
- No live cloud resources or paid infrastructure required.
- No claims of production security enforcement without corresponding evidence.

## 8. Initial Status

Architecture: Proposed.

Security controls: Proposed.

Attack scenarios: Planned.

Validation evidence: Not yet generated