# Project 5 — Security Validation Evidence

## Purpose

This directory contains validation evidence for the Secure AI Data and RAG Pipeline laboratory.

All scenarios use synthetic data and locally executed tests. The laboratory does not demonstrate production deployment or comprehensive protection against every attack variant.

## Full Regression

**Evidence:** `project5-full-regression.txt`

**Result:** 129 tests passed, 0 failures, 0 errors.

The regression suite covers ingestion, provenance verification, retrieval authorization, prompt-injection screening, output protection, security event recording, and integrated gateway behavior.

## Adversarial Scenario Evidence

| Scenario | Security objective | Evidence | Demonstrated result |
|---|---|---|---|
| RAG5-001 — Poisoned Document Ingestion | Distinguish provenance integrity from content safety | `rag5-001-poisoned-ingestion-validation.txt` | A provenance-valid poisoned document passes ingestion; the tested injection is rejected during downstream context preparation |
| RAG5-002 — Provenance Tampering | Detect unauthorized document modification | `rag5-002-provenance-tampering-validation.txt` | Modified content fails verification with an intact trusted record but passes after simulated registry compromise |
| RAG5-003 — Unauthorized Retrieval | Enforce role and document-level access restrictions | `rag5-003-end-to-end-access-denial.txt`, `retrieval-authorization-tests.txt` | Unauthorized retrieval is denied before context preparation or model invocation in the tested path |
| RAG5-004 — Retrieved-Content Prompt Injection | Detect and mitigate instruction hijacking | `rag5-004-instruction-hijack.txt`, `rag5-004-mitigation-validation.txt` | A tested payload initially induced instruction following; a targeted screening update subsequently blocked the same payload before model invocation |
| RAG5-005 — Sensitive-Information Extraction | Restrict release of synthetic sensitive values | `rag5-005-sensitive-output-validation.txt`, `rag5-005-end-to-end-validation.txt` | Tested synthetic email addresses and tokens were redacted before release |

## Supporting Evidence

- `ingestion-baseline-tests.txt` — Initial ingestion validation.
- `provenance-enforcement-tests.txt` — Provenance and integrity verification tests.
- `secure-context-integration-tests.txt` — Retrieval and context preparation validation.
- `retrieval-authorization-tests.txt` — Role and document-level authorization tests.
- `project5-full-regression.txt` — Latest complete automated regression.

## MITRE ATLAS and STRIDE

See:

- `../docs/atlas/atlas-mapping.md`
- `../docs/threat-model/stride-threat-model.md`

MITRE ATLAS mappings use the verified `ATLAS-2026.09` dataset. ATLAS supplements the STRIDE threat model rather than replacing it.

## Evidence Interpretation

A passing test establishes the observed behavior under its specified inputs and assumptions. It does not establish that a control is resistant to all adversarial variations.

Key limitations include:

- No authenticated provenance administration or tamper-resistant registry.
- No authenticated principal identity or protected grant administration.
- No comprehensive semantic poisoning or prompt-injection detection.
- No production-grade sensitive-data classification or DLP.
- No durable, tamper-resistant security event storage.
- No live cloud infrastructure or production security deployment.

Controls are described as implemented and tested only where corresponding code and validation evidence exist.

## Reproduction

From the repository root, run:

```bash
python3 -B -m unittest discover -s tests -p 'test_*.py' -v
```

The automated unit and integration tests use Python's standard library and do not require a running Ollama server. Separate live-model evaluations use a locally configured Ollama instance and may produce model-dependent results.