# Secure AI Data and RAG Pipeline

**Project 5 — AI Security Architecture Portfolio**

An offline-first security engineering laboratory examining document provenance, ingestion integrity, retrieval authorization, prompt-injection defenses, sensitive-information protection, and security event recording in retrieval-augmented generation (RAG) systems.

The project extends the earlier [Secure RAG Prompt Injection Lab](https://github.com/jupiter888/secure-rag-prompt-injection-lab) into a multi-boundary security architecture with adversarial testing, documented mitigation decisions, and evidence-linked threat modeling.

**Validation:** 129 automated tests passed, with zero failures or errors.

## 1. Security Objectives

The laboratory investigates five security questions:

1. Can a poisoned document enter a RAG corpus despite valid metadata and provenance?
2. Can an attacker bypass document integrity checks by manipulating provenance information?
3. Can retrieval authorization prevent unauthorized access across roles and document-specific permissions?
4. Can malicious instructions embedded in retrieved content manipulate an LLM?
5. Can output controls prevent selected sensitive values from being released?

Each scenario is evaluated against implemented controls, observed behavior, and remaining exposure.

## 2. Architecture

[View the secure RAG pipeline architecture diagram](diagrams/secure-rag-pipeline.md)

The architecture separates five trust boundaries:

| Boundary | Description | Security responsibility |
|---|---|---|
| TB-01 | Document Source → Ingestion Gateway | Source policy, metadata validation, and ingestion decisions |
| TB-02 | Ingestion Gateway → Approved Document Store | Provenance integrity and approved-document storage |
| TB-03 | User Identity → Retrieval Service | Role and document-level retrieval authorization |
| TB-04 | Retrieved Content → LLM | Untrusted-content screening and constrained context construction |
| TB-05 | LLM Output → User | Output validation, sensitive-value redaction, and release decisions |

The system uses synthetic documents classified as `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, or `RESTRICTED`.

### Implemented Components

**Secure ingestion:** Validates document metadata, trusted-source policy, SHA-256 integrity, and independently registered provenance. Rejected submissions generate in-memory quarantine decisions.

**Retrieval authorization:** Applies role-based classification permissions and document-specific principal grants before returning document content.

**Retrieved-content security:** Screens selected prompt-injection patterns and constructs model messages that explicitly distinguish untrusted reference material from instructions.

**Unified secure RAG gateway:** Coordinates authorized retrieval, context preparation, local model generation, output protection, and security decision recording.

**Output protection:** Redacts selected synthetic email addresses and token patterns. The laboratory blocks `RESTRICTED` classification output through its protected model gateway.

**Security events:** Records selected security decisions using structured, metadata-only, in-memory events.

These controls are laboratory implementations, not production-grade identity, provenance, DLP, or monitoring services.

## 3. Threat Model and Adversarial Findings

The project uses STRIDE to analyze security boundaries and MITRE ATLAS to supplement the analysis of applicable AI-specific attack techniques.

| Scenario | Attack surface | Observed result |
|---|---|---|
| RAG5-001 — Poisoned Document Ingestion | Document ingestion and retrieved content | A provenance-valid poisoned document passed ingestion; the tested malicious instructions were blocked during downstream context preparation |
| RAG5-002 — Document Provenance Tampering | Document integrity and trusted provenance registry | Tampered content was rejected with an intact registry but passed verification after simulated compromise of the trusted reference record |
| RAG5-003 — Unauthorized Cross-Role Retrieval | Retrieval permissions and document grants | Tested unauthorized requests were denied before model-context preparation |
| RAG5-004 — Retrieved-Content Prompt Injection | Untrusted retrieved documents | A local model followed a tested malicious instruction; a subsequent targeted screening control blocked replay of that payload |
| RAG5-005 — Sensitive-Information Extraction | Generated output | Selected synthetic email addresses and tokens were redacted before output release |

### MITRE ATLAS Mapping

The mapping references the verified **MITRE ATLAS 2026.09** dataset.

- `AML.T0070` — RAG Poisoning: applicable to RAG5-001 and conditionally related to RAG5-002.
- `AML.T0051.001` — Indirect LLM Prompt Injection: applicable to RAG5-004.
- `AML.T0057` — LLM Data Leakage: applicable to RAG5-005.

RAG5-003 is analyzed primarily through STRIDE and retrieval-authorization controls; no ATLAS technique is assigned solely for conventional access-control failure.

[Full MITRE ATLAS mapping](docs/atlas/atlas-mapping.md) · [STRIDE threat model](docs/threat-model/stride-threat-model.md)

## 4. Validation Evidence

**Latest full regression:** 129 tests passed, zero failures, zero errors.

The automated tests cover document validation, source authorization, provenance integrity, retrieval permissions, document-specific grants, content screening, context preparation, output redaction, security events, and gateway orchestration.

Adversarial evidence includes:

- Provenance-valid poisoned-document ingestion and downstream rejection.
- Recomputed-digest tampering and simulated trusted-registry compromise.
- Unauthorized retrieval denial before model invocation.
- A successful local-model instruction-hijacking attempt followed by targeted mitigation validation.
- Synthetic sensitive-value redaction in an integrated RAG workflow.

[Browse the evidence index](evidence/README.md) · [Full regression results](evidence/project5-full-regression.txt)

Passing tests demonstrate specific behaviors under laboratory assumptions. They do not establish comprehensive protection against all attack variants.

## 5. Repository Structure

```text
Project5/
├── README.md
├── config/
├── data/
│   ├── quarantine/
│   └── synthetic/
├── diagrams/
│   └── secure-rag-pipeline.md
├── docs/
│   ├── architecture/
│   ├── atlas/
│   ├── security-controls/
│   └── threat-model/
├── evidence/
│   ├── README.md
│   └── ... validation artifacts
├── src/
│   ├── ingestion/
│   ├── retrieval/
│   └── security/
└── tests/
```

## 6. Reproducing the Tests

### Requirements

- Python 3 with standard-library support for the included automated tests.
- Optional: Ollama and the `qwen2.5:3b` model for local live-model evaluations.

Run the full automated regression suite from the repository root:

```bash
python3 -B -m unittest discover -s tests -p 'test_*.py' -v
```

The automated unit and integration tests do not require live cloud services or an Ollama server.

### Optional Local Model Evaluations

Selected evaluation scripts use a locally running Ollama API at `http://127.0.0.1:11434` with `qwen2.5:3b`.

These evaluations exercise model behavior under synthetic attack conditions. Results can vary with model version and generation behavior, even when the evaluation configuration is held constant.

No external LLM API keys or live AWS resources are required.

## 7. Security Limitations

The following capabilities are **not implemented** as production-grade security controls:

- Authenticated user identity and trusted principal establishment.
- Authenticated administration of document grants and provenance records.
- Tamper-resistant provenance storage and cryptographic publisher authentication.
- Comprehensive semantic document-poisoning detection.
- Generalizable prompt-injection prevention across adversarial variations.
- Comprehensive sensitive-data detection and field-level release policies.
- Durable, tamper-evident audit logging and operational alerting.
- Enforcement that prevents direct bypass of internal Python components.
- Production deployment, distributed state management, and operational hardening.

The trusted registries, document stores, authorization grants, and event records are maintained in mutable application memory.

Security claims are therefore limited to the tested code paths and documented trust assumptions.

## 8. Documentation

- [System architecture](docs/architecture/system-architecture.md)
- [Architecture diagram](diagrams/secure-rag-pipeline.md)
- [STRIDE threat model](docs/threat-model/stride-threat-model.md)
- [MITRE ATLAS mapping](docs/atlas/atlas-mapping.md)
- [Ingestion control assessment](docs/security-controls/ingestion-control-assessment.md)
- [Retrieval authorization assessment](docs/security-controls/retrieval-authorization-assessment.md)
- [Prompt-injection evaluation rubric](docs/security-controls/prompt-injection-evaluation-rubric.md)
- [Output security assessment](docs/security-controls/output-security-assessment.md)
- [Unified gateway assessment](docs/security-controls/unified-gateway-assessment.md)
- [Validation evidence index](evidence/README.md)

## 9. Scope and Responsible Use

All documents, identities, tokens, and attack scenarios are synthetic.

The project is intended for controlled security research, architecture evaluation, and reproducible defensive testing. It does not require access to third-party systems or production data.

## 10. Licensing

This repository uses separate licensing terms for software and
original security architecture documentation.

**Code and synthetic examples — MIT License**

Original software, automated tests, and synthetic examples in
`src/`, `tests/`, `config/`, and `data/synthetic/` are covered by
[CODE-LICENSE.md](CODE-LICENSE.md).

**Architecture documentation and research — All Rights Reserved**

Original architecture documentation, diagrams, threat models,
security assessments, and validation evidence are covered by
[DOCUMENTATION-NOTICE.md](DOCUMENTATION-NOTICE.md).

The MIT License does not extend to materials covered by the
documentation copyright notice.

Third-party materials remain subject to their respective terms.

---

**Portfolio focus:** AI security architecture, secure RAG engineering,
adversarial validation, trust-boundary enforcement, threat modeling,
and evidence-based control assessment.

---

**Portfolio focus:** AI security architecture, secure RAG engineering, adversarial validation, trust-boundary enforcement, threat modeling, and evidence-based control assessment.