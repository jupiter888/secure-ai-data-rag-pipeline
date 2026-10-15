# Project 5 — STRIDE Threat Model

## 1. System

Secure AI Data and RAG Pipeline

Architecture reference: [Secure RAG Pipeline](../../diagrams/secure-rag-pipeline.md)

## 2. Security Objectives

- Preserve the integrity and provenance of ingested documents.
- Prevent unauthorized ingestion and retrieval.
- Enforce document-level access restrictions.
- Prevent untrusted retrieved content from controlling the LLM.
- Prevent unauthorized disclosure through generated responses.
- Maintain auditable evidence of security decisions.

## 3. Threat Scenarios

### RAG5-001 — Poisoned Document Ingestion

- **Boundary:** TB-01
- **STRIDE:** Spoofing, Tampering
- **Attacker control:** Synthetic document content and attempted source metadata manipulation
- **Threat:** An attacker submits unauthorized or malicious content for inclusion in the approved document store.
- **Proposed controls:** Source authorization, format validation, provenance checks, quarantine
- **Validation:** Test unauthorized ingestion and confirm rejection without approved-store modification
- **Status:** Proposed

### RAG5-002 — Document Provenance Tampering

- **Boundary:** TB-02
- **STRIDE:** Tampering
- **Attacker control:** Document content or integrity metadata
- **Threat:** A document is modified after its trusted integrity metadata was established.
- **Proposed controls:** SHA-256 integrity verification, trusted metadata handling, quarantine
- **Validation:** Modify document content while retaining the original digest and verify rejection
- **Status:** Proposed

### RAG5-003 — Unauthorized Cross-Role Retrieval

- **Boundary:** TB-03
- **STRIDE:** Information Disclosure, Elevation of Privilege
- **Attacker control:** Retrieval requests submitted under a lower-privilege synthetic identity
- **Threat:** A user retrieves documents outside their authorized access scope.
- **Proposed controls:** Identity validation, document-level authorization, deny-by-default retrieval
- **Validation:** Attempt retrieval of restricted documents using an unauthorized identity
- **Status:** Proposed

### RAG5-004 — Retrieved-Content Prompt Injection

- **Boundary:** TB-04
- **STRIDE:** Tampering
- **Attacker control:** Text within a retrieved document
- **Threat:** Embedded instructions attempt to override trusted system requirements or manipulate model behavior.
- **Proposed controls:** Trusted instruction boundaries, content isolation, output validation
- **Validation:** Inject adversarial instructions into synthetic retrieved content and measure whether the requested deviation occurs
- **Status:** Proposed

### RAG5-005 — Sensitive-Information Extraction

- **Boundary:** TB-05
- **STRIDE:** Information Disclosure
- **Attacker control:** User queries and attempted output manipulation
- **Threat:** A response exposes protected document content to an unauthorized principal.
- **Proposed controls:** Pre-retrieval authorization, sensitive-data redaction, output disclosure checks
- **Validation:** Attempt unauthorized extraction and verify that protected content is not returned
- **Status:** Proposed

## 4. Cross-Cutting Threats

### Repudiation and Evidence Integrity

Security decisions may become difficult to investigate if event records are missing, incomplete, or mutable.

**Proposed controls:**

- Structured security-event records
- Request and document identifiers
- Control-decision outcomes
- Minimal logging of protected content
- Reproducible test evidence

## 5. MITRE ATLAS Integration

Applicable AI-specific attack scenarios will be mapped separately in `docs/atlas/`.

Each mapping must include a verified technique identifier, prerequisites, relevant controls, validation evidence, and residual risk.

MITRE ATLAS complements this STRIDE analysis and does not replace it.

## 6. Assessment Status

All controls and validation activities are currently proposed.

No implementation or security test results are claimed by this document.