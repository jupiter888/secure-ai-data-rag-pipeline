# Secure AI Data and RAG Pipeline — Data-Flow Diagram

## Purpose

This diagram represents the logical data flows, trust boundaries, and security decisions in the Project 5 synthetic RAG pipeline.

It distinguishes implemented laboratory controls from assumptions that would require stronger enforcement in a production environment.

## Data-Flow Diagram

```mermaid
flowchart TD
    SOURCE["E1: Synthetic Document Publisher"]
    USER["E2: Caller-Supplied Principal"]
    QUESTION["E3: User Question"]

    subgraph TB1["TB-01: Untrusted Source to Ingestion"]
        INGEST["P1: Ingestion Gateway"]
        VALIDATE["P2: Metadata and Source Validation"]
        PROVENANCE["P3: Provenance Verification"]
    end

    subgraph TB2["TB-02: Approved Document Storage"]
        STORE[("D1: Approved Documents")]
        REGISTRY[("D2: Trusted Provenance Registry")]
        QUARANTINE[("D3: In-Memory Quarantine Decisions")]
    end

    subgraph TB3["TB-03: Identity and Retrieval Authorization"]
        RETRIEVE["P4: Retrieval Gateway"]
        RBAC["P5: Role and Document-Grant Authorization"]
        GRANTS[("D4: Document Access Grants")]
    end

    subgraph TB4["TB-04: Retrieved Content to LLM"]
        SCREEN["P6: Retrieved-Content Screening"]
        CONTEXT["P7: Context Builder"]
        MODEL["P8: Local Ollama Model"]
    end

    subgraph TB5["TB-05: Model Output to User"]
        GUARD["P9: Output Protection"]
        RESPONSE["E4: Released Response"]
    end

    EVENTS[("D5: In-Memory Security Events")]

    SOURCE -->|"Document content and claimed metadata"| INGEST
    INGEST --> VALIDATE
    VALIDATE -->|"Source and format accepted"| PROVENANCE
    REGISTRY -->|"Expected metadata and SHA-256"| PROVENANCE
    VALIDATE -->|"Rejected input"| QUARANTINE
    PROVENANCE -->|"Failed verification"| QUARANTINE
    PROVENANCE -->|"Verified document"| STORE

    USER -->|"Principal ID and role"| RETRIEVE
    QUESTION -->|"Question and document ID"| RETRIEVE
    RETRIEVE --> RBAC
    GRANTS --> RBAC
    RBAC -->|"Authorized document ID"| STORE
    STORE -->|"Approved document content"| RETRIEVE
    RBAC -->|"Denied request"| EVENTS

    RETRIEVE -->|"Authorized retrieved content"| SCREEN
    SCREEN -->|"Suspicious content rejected"| EVENTS
    SCREEN -->|"Screened reference content"| CONTEXT
    CONTEXT -->|"System instruction and untrusted reference data"| MODEL
    MODEL -->|"Generated answer"| GUARD
    GUARD -->|"Approved or redacted answer"| RESPONSE
    GUARD -->|"Blocked output"| EVENTS

    INGEST -.->|"Selected security decisions"| EVENTS
    RETRIEVE -.->|"Selected security decisions"| EVENTS
    GUARD -.->|"Selected security decisions"| EVENTS
```

## Trust Boundaries

| Boundary | Security concern | Implemented laboratory control |
|---|---|---|
| TB-01 | Untrusted documents entering the pipeline | Source allowlist and metadata validation |
| TB-02 | Integrity of approved document content | SHA-256 verification against provenance records |
| TB-03 | Unauthorized retrieval of classified documents | Role permissions and document-specific grants |
| TB-04 | Retrieved content influencing model instructions | Pattern-based screening and context separation |
| TB-05 | Disclosure through generated responses | Restricted-output blocking and synthetic identifier redaction |

## Security Assumptions and Limitations

- Publisher identity is not cryptographically authenticated.
- The provenance registry is mutable and maintained in memory.
- The principal identity and role are supplied by the caller; no independent authentication is implemented.
- Document grants are configured through an unauthenticated laboratory interface.
- Retrieval authorization is enforced by the demonstrated gateway, not by an independently secured storage layer.
- Prompt-injection screening is pattern-based and can be bypassed by novel or encoded payloads.
- The local model is not guaranteed to obey trust-boundary instructions.
- Security-event recording is selective, in memory, and not tamper-resistant.
- The diagram describes logical control flow, not independently isolated runtime services.

## Related Artifacts

- [System Architecture](../docs/architecture/system-architecture.md)
- [STRIDE Threat Model](../docs/threat-model/stride-threat-model.md)
- [MITRE ATLAS Mapping](../docs/atlas/atlas-mapping.md)
- [Security Evidence](../evidence/README.md)