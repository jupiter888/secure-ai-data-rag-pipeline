# Project 5 — Retrieval Authorization Security Assessment

## 1. Assessment Scope

Threat scenario: RAG5-003 — Unauthorized Cross-Role Retrieval.

This assessment covers role/classification authorization, document-specific access grants, and enforcement at the retrieval gateway.

Evidence: `../../evidence/retrieval-authorization-tests.txt`

## 2. Implemented and Tested Controls

| Control | Implementation | Status |
|---|---|---|
| Role/classification allowlist | `src/retrieval/authorization.py` | Tested |
| Deny-by-default unknown roles | `src/retrieval/authorization.py` | Tested |
| Explicit document grants | `src/retrieval/document_access.py` | Tested |
| Role restrictions override grants | `src/retrieval/document_access.py` | Tested |
| Cross-team access denial | `src/retrieval/document_access.py` | Tested |
| Retrieval from approved store only | `src/retrieval/gateway.py` | Tested |
| Content excluded from denied responses | `src/retrieval/gateway.py` | Tested |
| Rejected ingestion excluded from retrieval | `src/retrieval/gateway.py` | Tested |

## 3. Adversarial Validation

### Vertical Authorization

An ANALYST principal was explicitly granted access to a CONFIDENTIAL document.

Expected: Denied because the role lacks classification permission.

Observed: `RETRIEVAL_DENIED`.

### Horizontal Authorization

A RESEARCHER principal attempted to retrieve another team's CONFIDENTIAL document without an explicit grant.

Expected: Denied despite having sufficient classification permission.

Observed: `DOCUMENT_ACCESS_DENIED`.

### Ingestion Boundary

A document rejected for missing trusted provenance was requested through the retrieval gateway.

Expected: Document unavailable, regardless of any configured access grant.

Observed: `DOCUMENT_NOT_AVAILABLE`.

### Information Exposure

Denied retrieval responses were checked for document content and document identifiers.

Observed: Both fields were `None` in the tested denial paths.

## 4. Remaining Limitations

- Principal identities and roles are supplied by the caller rather than authenticated.
- Document grants are configured through an unauthenticated administrative method.
- Approved documents and grants remain mutable in process memory.
- Other Python code with direct access to these objects can bypass the gateway.
- No persistent authorization audit trail has been implemented.
- No document ownership enforcement exists beyond explicit principal grants.
- The tests do not establish security against concurrent policy changes or distributed deployment.

## 5. Proposed Improvements

- Authenticate principals and derive roles from trusted identity claims.
- Restrict grant administration to authorized administrators.
- Protect approved documents and grants behind controlled storage interfaces.
- Add structured, content-minimized authorization audit events.
- Test policy changes, revocation, and additional adversarial access paths.

All improvements above are proposed, not implemented.

## 6. MITRE ATLAS Relationship

RAG5-003 remains primarily a conventional authorization and information-disclosure threat modeled through STRIDE.

No MITRE ATLAS technique is assigned solely because unauthorized document retrieval is attempted.

A separate ATLAS mapping may become applicable when unauthorized retrieval forms part of a demonstrated AI-specific attack chain.

## 7. Validation Summary

- Automated tests: 60
- Passing tests: 60
- Failed tests: 0
- Evidence file: `evidence/retrieval-authorization-tests.txt`
- Environment: Local Python standard-library test harness
- Live cloud resources: None

## 8. Residual Risk Assessment

**Status: Partially mitigated within the synthetic laboratory trust model.**

The implemented gateway demonstrates fail-closed retrieval decisions based on role/classification permissions and explicit document grants.

The tests establish that the evaluated unauthorized requests do not return document content through this gateway.

They do not establish authenticated identity, tamper-resistant policy administration, or production-grade isolation of the underlying document store.