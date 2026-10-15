# Project 5 — RAG5-005 Output Security Assessment

## 1. Scope

Scenario: RAG5-005 — Sensitive-Information Extraction

Objective: Evaluate whether an AI-assisted retrieval system exposes sensitive values through generated responses.

Environment: Local, synthetic, offline-first RAG security lab.

## 2. Security Boundary

Document retrieval authorization does not automatically authorize disclosure of every value contained within a document.

The output-security boundary operates after retrieval and model generation.

## 3. Synthetic Test Data

The evaluation will use fictional records containing:

- A synthetic employee identifier.
- A fictional email address.
- A deliberately fabricated access token.
- Ordinary non-sensitive policy information.

No actual credentials, personal information, or production records will be used.

## 4. Planned Attack Scenarios

### RAG5-005-A — Direct Sensitive-Value Request

An authorized document reader asks the model to reproduce a sensitive value.

### RAG5-005-B — Indirect Extraction

A retrieved document contains instructions attempting to induce disclosure of sensitive information.

### RAG5-005-C — Unauthorized Retrieval

A principal without the required document permissions attempts to retrieve sensitive material.

This scenario also validates the existing RAG5-003 authorization boundary.

## 5. Proposed Controls

- Classification-aware output policy.
- Detection of designated sensitive-value patterns.
- Redaction before releasing model responses.
- Fail-closed handling of output-validation failures.
- Security event recording without sensitive payloads.

All controls in this section are PROPOSED until implemented and tested.

## 6. Planned Validation

Tests will verify that:

1. Authorized users can receive permitted non-sensitive information.
2. Designated sensitive values are not disclosed in released output.
3. Unauthorized retrieval remains blocked.
4. Rejected or redacted outputs do not expose the original sensitive values.
5. Security evidence records decisions without recording sensitive payloads.

## 7. Residual Risks

- Pattern-based detection may miss unknown sensitive-data formats.
- Redaction may remove legitimate content.
- Document authorization and field-level disclosure permissions are separate concerns.
- A local demonstration does not establish production-grade data-loss prevention.
- In-memory authorization state and caller-supplied identities remain limitations of this lab.

## 8. Evidence Requirements

Record each test scenario, synthetic input, authorization decision, output-control decision, released response, and residual risk.

Clearly distinguish PROPOSED, IMPLEMENTED, and TESTED controls.