
# Project 5 — MITRE ATLAS Threat Mapping

## 1. Purpose

This document supplements the Project 5 STRIDE threat model with AI-specific adversarial techniques from MITRE ATLAS.

MITRE ATLAS is used to classify applicable adversarial behaviors, connect attack scenarios to implemented controls, and identify remaining security gaps.

It does not replace STRIDE, conventional authorization analysis, integrity verification, or security-control testing.

Related artifacts:

- [Secure RAG Pipeline Architecture](../../diagrams/secure-rag-pipeline.md)
- [STRIDE Threat Model](../threat-model/stride-threat-model.md)
- [System Architecture](../architecture/system-architecture.md)
- [Unified Gateway Security Assessment](../security-controls/unified-gateway-assessment.md)

## 2. Framework Reference

- Framework: MITRE ATLAS
- Official catalog: https://atlas.mitre.org/
- Official data repository: https://github.com/mitre-atlas/atlas-data
- Verified dataset: `dist/v6/ATLAS-2026.09.yaml`
- Content version: `2026.09`
- Data format: v6
- Verification date: 2026-10-14
- Technique verification: CONFIRMED
- Mapping status: Evidence-linked
- Implementation status: Mixed; individual controls are classified below

### Mapping Principles

1. Assign an ATLAS technique only where the adversarial behavior reasonably matches the technique definition.
2. Preserve STRIDE classifications regardless of ATLAS applicability.
3. Distinguish demonstrated attacks from hypothetical attack paths.
4. Distinguish implemented controls from proposed controls.
5. Treat passing tests as evidence for specific tested conditions, not comprehensive security guarantees.
6. Record residual risk even when a control successfully blocks a tested attack.

## 3. Scenario Mapping

### RAG5-001 — Poisoned Document Ingestion

**ATLAS technique:** RAG Poisoning

**Verified technique ID:** AML.T0070

**Official reference:** https://atlas.mitre.org/techniques/AML.T0070

**Mapping status:** Verified against ATLAS-2026.09

**Prerequisite:** An attacker can influence documents submitted to the ingestion pipeline.

**Attacker-controlled surface:** Submitted document content, source identifiers, or associated metadata.

**Attack objective:** Introduce malicious or misleading material into the retrieval corpus so that downstream model responses may be manipulated.

**Implemented controls:**

- Document metadata validation
- Source-authorization policy checks
- SHA-256 integrity validation
- Independent provenance-record verification
- Rejected-document quarantine decisions
- Duplicate document identifier rejection

**Tested behavior:**

Two complementary adversarial tests demonstrate the distinction
between document integrity and document safety.

1. `test_authorized_poisoned_document_passes_ingestion`
   confirms that a document containing malicious instructions
   is accepted when its source policy, metadata, and trusted
   provenance record are valid.

2. `test_authorized_poisoned_document_blocked_downstream`
   confirms that the same malicious instruction pattern is
   rejected during secure context preparation after ingestion
   and retrieval authorization.

**Evidence:**

- `evidence/ingestion-baseline-tests.txt`
- `evidence/provenance-enforcement-tests.txt`
- `evidence/rag5-001-poisoned-ingestion-validation.txt`
- `evidence/project5-full-regression.txt`

**Control status:**

- Metadata validation: IMPLEMENTED AND TESTED
- Source policy enforcement: IMPLEMENTED AND TESTED
- Provenance verification: IMPLEMENTED AND TESTED
- Rejection and quarantine decisions: IMPLEMENTED AND TESTED
- Downstream screening of selected malicious instructions: IMPLEMENTED AND TESTED
- Semantic poisoning detection at ingestion: NOT IMPLEMENTED
- Comprehensive RAG poisoning prevention: NOT DEMONSTRATED

**Observed outcome:**

The malicious document passed ingestion because its metadata,
source policy, and registered digest were valid.

The downstream secure context pipeline recognized the tested
instruction-hijacking pattern and rejected the document before
constructing model context.

The dedicated validation suite passed 21 tests.

This demonstrates a layered mitigation against the selected
payload, not comprehensive protection against RAG poisoning.

**Residual risk:**

A malicious but authorized source may introduce adversarial content that passes metadata, source, and integrity validation.

Source identity is represented by a claimed identifier rather than cryptographically authenticated publisher identity.

Quarantine is maintained in memory rather than in a protected persistent repository.

---

### RAG5-002 — Document Provenance Tampering

**ATLAS relationship:** Conditional relationship to RAG Poisoning.

**Verified related technique:** AML.T0070 — RAG Poisoning

**Official reference:** https://atlas.mitre.org/techniques/AML.T0070

**Mapping qualification:**

Provenance tampering contributes to RAG Poisoning when it is used to introduce or replace malicious content in the retrieval corpus.

General integrity tampering remains a STRIDE threat. No independent ATLAS technique is assigned solely because a document digest changes.

**Prerequisite:**

An attacker can modify submitted document content or integrity metadata. The registry-compromise scenario additionally assumes direct write access to the trusted provenance registry.

**Attacker-controlled surface:**

- Submitted document content
- Submitted SHA-256 digest
- Submitted provenance metadata
- Trusted provenance records, if the registry is compromised

**Attack objective:**

Replace or modify trusted document content without detection, potentially allowing malicious material to enter the approved retrieval corpus.

**Implemented controls:**

- Content SHA-256 calculation
- Document metadata validation
- Comparison against an independently registered expected digest
- Comparison against trusted source, classification, and owner metadata
- Rejection of inconsistent document content or provenance
- Duplicate provenance registration rejection

**Tested behavior:**

The provenance validation tests demonstrate:

1. Valid documents pass verification when their content and metadata match independently registered provenance records.

2. Modified document content is rejected when its digest differs from the trusted reference.

3. Recomputing the submitted document digest does not bypass verification against the independently registered expected digest.

4. Source identity, classification, and owner mismatches are rejected.

5. Missing provenance records, invalid trusted digests, and duplicate registrations are rejected.

6. A controlled registry-compromise simulation demonstrates that directly replacing the trusted expected digest allows modified content to pass verification.

The registry-compromise test first confirms that the modified document fails verification against the original trusted record. It then replaces the trusted digest and verifies that the same document is accepted.

This simulation assumes registry write access. It does not demonstrate a remote exploit or a method of obtaining that access.

**Evidence:**

- `evidence/provenance-enforcement-tests.txt`
- `evidence/rag5-002-provenance-tampering-validation.txt`
- `evidence/project5-full-regression.txt`

**Control status:**

- Content SHA-256 verification: IMPLEMENTED AND TESTED
- Independent provenance comparison: IMPLEMENTED AND TESTED
- Source and metadata consistency verification: IMPLEMENTED AND TESTED
- Duplicate registration rejection: IMPLEMENTED AND TESTED
- Rejection of selected provenance mismatches: IMPLEMENTED AND TESTED
- Authenticated provenance administration: NOT IMPLEMENTED
- Tamper-resistant provenance storage: NOT IMPLEMENTED
- Cryptographic publisher authentication: NOT IMPLEMENTED
- Detection of unauthorized trusted-record modification: NOT IMPLEMENTED

**Observed outcome:**

The original trusted provenance record correctly rejected modified document content with a recomputed SHA-256 digest.

After simulated compromise of the trusted registry, the same modified document passed verification because its digest matched the compromised reference record.

The dedicated provenance validation suite passed 9 tests.

The result demonstrates that document integrity verification is dependent on the integrity of the trusted provenance registry.

**Residual risk:**

An adversary with write access to the trusted provenance registry could replace expected digests and undermine document integrity verification.

The registry is maintained in memory, its administrative registration interface is not authenticated, and its underlying records can be modified directly.

SHA-256 establishes content consistency relative to a trusted reference. It does not independently establish publisher authenticity, content safety, or protection against a compromised reference record.

Production deployment would require authenticated administrative operations, restricted write access, durable and tamper-evident provenance storage, and appropriate audit controls. These protections are not implemented in this laboratory.

**Assessment conclusion:**

RAG5-002 demonstrates effective detection of selected document and metadata tampering attempts when the trusted provenance registry remains intact.

It also demonstrates a consequential trust-boundary limitation: compromising the reference registry can defeat digest-based verification.

The implemented controls provide tested integrity enforcement within the laboratory's stated assumptions, not end-to-end provenance authenticity or tamper-resistant storage.

---

### RAG5-003 — Unauthorized Cross-Role Retrieval

**ATLAS relationship:** No independent technique assigned.

**Technique ID:** Not assigned.

**Mapping qualification:**

This scenario primarily concerns authorization enforcement, information disclosure, and potential privilege escalation.

It remains within the STRIDE threat model. An ATLAS technique should not be assigned merely to increase framework coverage.

**Prerequisite:** An attacker can submit retrieval requests using a synthetic principal.

**Attacker-controlled surface:** Retrieval requests, claimed principal identifiers, roles, and requested document identifiers.

**Attack objective:** Retrieve documents outside the requesting principal's permitted scope.

**Implemented controls:**

- Role-based classification permissions
- Document-specific access grants
- Deny-by-default retrieval
- Authorization before content release
- Unified gateway rejection before model invocation
- Structured recording of selected retrieval decisions

**Tested behavior:**

Unauthorized requests are denied without releasing document content.

The end-to-end access-denial test verifies that the model-generation step is not invoked for a denied request.

**Evidence:**

- `evidence/retrieval-authorization-tests.txt`
- `evidence/rag5-003-end-to-end-access-denial.txt`
- `evidence/project5-full-regression.txt`

**Control status:**

- Role-based authorization: IMPLEMENTED AND TESTED
- Document-level authorization: IMPLEMENTED AND TESTED
- Denial before model invocation: IMPLEMENTED AND TESTED
- Authenticated principal identity: NOT IMPLEMENTED
- Authenticated grant administration: NOT IMPLEMENTED

**Observed outcome:**

Selected unauthorized retrieval attempts are denied before model execution.

**Residual risk:**

Principals are caller-supplied rather than authenticated.

Access grants are held in mutable memory, and grant administration is not protected by a separate authenticated control plane.

Direct access to internal Python objects may bypass the intended gateway.

The laboratory does not demonstrate production-grade identity verification or process isolation.

---

### RAG5-004 — Retrieved-Content Prompt Injection

**ATLAS technique:** LLM Prompt Injection — Indirect

**Verified subtechnique ID:** AML.T0051.001

**Official reference:** https://atlas.mitre.org/techniques/AML.T0051.001

**Mapping status:** Verified against ATLAS-2026.09

**Prerequisite:** Attacker-controlled instructions appear inside retrieved reference material.

**Attacker-controlled surface:** Retrieved document text.

**Attack objective:** Induce the language model to follow lower-trust document instructions instead of treating the document solely as reference material.

**Implemented controls:**

- Retrieved-content screening
- Pattern-based detection of selected instruction-hijacking payloads
- Explicit untrusted-context labeling
- Separation of trusted instructions from reference content
- JSON serialization of retrieved content
- Rejection of recognized malicious content before model invocation
- Unified gateway orchestration
- Structured recording of selected screening rejections

**Tested behavior:**

A local model evaluation demonstrated that a malicious retrieved document could induce the model to append the attacker-selected marker `ORBITAL-PINEAPPLE-742` to an otherwise correct answer.

The screening controls were subsequently strengthened to detect the tested instruction-hijacking pattern.

A replay of that payload was rejected during context preparation, before model invocation.

**Evidence:**

- `evidence/rag5-004-instruction-hijack.txt`
- `evidence/rag5-004-mitigation-validation.txt`
- `evidence/secure-context-integration-tests.txt`
- `evidence/project5-full-regression.txt`

**Control status:**

- Retrieved-content screening: IMPLEMENTED AND TESTED
- Trusted/untrusted context separation: IMPLEMENTED AND TESTED
- Targeted instruction-hijack rejection: IMPLEMENTED AND TESTED
- Comprehensive prompt-injection prevention: NOT DEMONSTRATED

**Observed outcome:**

The baseline evaluation demonstrated successful instruction hijacking and answer contamination.

The targeted mitigation blocked the previously successful payload before it reached the model.

This result establishes mitigation effectiveness for the tested payload, not universal prompt-injection resistance.

**Residual risk:**

Novel, encoded, multilingual, obfuscated, or semantically indirect payloads may evade pattern matching.

Quoted malicious instructions may trigger false positives.

Context separation and JSON serialization do not guarantee that a language model will respect the intended trust boundary.

---

### RAG5-005 — Sensitive-Information Extraction

**ATLAS technique:** LLM Data Leakage, where the scenario concerns protected information disclosed through generated output.

**Verified technique ID:** AML.T0057

**Official reference:** https://atlas.mitre.org/techniques/AML.T0057

**Mapping status:** Verified against ATLAS-2026.09

**Prerequisite:** The model receives sensitive information through authorized context or an incorrectly authorized retrieval path.

**Attacker-controlled surface:** User questions and attempts to elicit protected information from model output.

**Attack objective:** Cause the system to disclose protected data to an unauthorized recipient or release sensitive values in an otherwise authorized response.

**Implemented controls:**

- Role-based and document-level retrieval authorization
- Restricted-classification output blocking
- Synthetic email-address redaction
- Synthetic token redaction
- Output validation before response release
- Unified gateway orchestration
- Structured recording of selected output-protection decisions

**Tested behavior:**

A local model evaluation produced synthetic sensitive values in its generated response.

The output guard replaced the recognized email address and synthetic token before the response was released.

An integrated evaluation exercised ingestion, authorized retrieval, context construction, model generation, and output redaction.

Separate access-denial tests verified that selected unauthorized retrieval requests were rejected before model execution.

**Evidence:**

- `evidence/rag5-005-sensitive-output-validation.txt`
- `evidence/rag5-005-end-to-end-validation.txt`
- `evidence/rag5-003-end-to-end-access-denial.txt`
- `evidence/project5-full-regression.txt`

**Control status:**

- Sensitive-output pattern detection: IMPLEMENTED AND TESTED
- Synthetic email/token redaction: IMPLEMENTED AND TESTED
- Restricted-output blocking: IMPLEMENTED AND TESTED
- Unauthorized retrieval rejection: IMPLEMENTED AND TESTED
- Comprehensive data-loss prevention: NOT IMPLEMENTED

**Observed outcome:**

Recognized synthetic sensitive values were redacted from tested model responses before release.

Selected unauthorized retrieval attempts were blocked before model invocation.

**Residual risk:**

Regex-based inspection does not detect every form of sensitive information.

Paraphrased, encoded, fragmented, or semantically inferred disclosures may bypass the current output guard.

The model may still process sensitive data internally before output inspection.

Successful redaction does not establish that every possible information-disclosure path is blocked.

## 4. Evidence Requirements

Each scenario should provide:

1. Exact ATLAS technique ID, name, official URL, and catalog revision or retrieval date where applicable.
2. Attack prerequisites and attacker-controlled surface.
3. Threat objective and relevant trust boundary.
4. Implemented preventive and detective controls.
5. Proposed or unimplemented controls clearly distinguished from tested controls.
6. Test identifier and observed outcome.
7. Evidence artifact location.
8. Remaining limitations and residual risk.

Evidence must be synthetic and sanitized before being stored in the iCloud-synchronized project directory or committed to Git.

A passing test must not be presented as proof of comprehensive security.

## 5. Assessment Status

**Mapping status:** Evidence-linked; applicable technique identifiers verified against ATLAS-2026.09

The Project 5 implementation has passed **126 automated regression tests**, with zero failures and zero errors.

This count includes component tests, integration tests, authorization tests, security-event tests, and other automated validation. It does not represent 126 distinct adversarial attack scenarios.

### Implemented and Tested Controls

- Document metadata validation and trusted-source policy checks
- Independent document provenance and SHA-256 verification
- Role-based and document-specific retrieval authorization
- Retrieved-content screening and context separation
- Targeted prompt-injection mitigation
- Synthetic sensitive-output redaction
- Restricted-classification output blocking
- Unified RAG gateway orchestration
- In-memory structured security-event recording

### Demonstrated Adversarial Outcomes

- Selected unauthorized or invalid ingestion conditions rejected
- Selected provenance and integrity mismatches rejected
- Unauthorized retrieval denied before model invocation
- Successful instruction-hijacking baseline demonstrated
- Previously successful instruction-hijacking payload subsequently blocked
- Synthetic sensitive values redacted from generated responses

### Outstanding Security Limitations

- No authenticated publisher identities
- No authenticated principal identities or grant administration
- No protected persistent provenance registry
- No semantic document-poisoning detector
- No comprehensive prompt-injection prevention
- No comprehensive data-loss prevention
- No tamper-resistant or persistent audit logging
- No production monitoring or alerting
- No enforcement preventing direct bypass of internal Python interfaces

### Framework Conclusion

MITRE ATLAS provides AI-specific adversarial context for applicable scenarios.

STRIDE remains the primary architectural threat-modeling framework for spoofing, tampering, repudiation, information disclosure, denial of service, and elevation of privilege.

The combined analysis supports an evidence-based security architecture assessment without overstating the effectiveness of the implemented controls.