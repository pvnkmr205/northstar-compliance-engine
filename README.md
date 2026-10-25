# Northstar Privacy Compliance Audit Engine

An enterprise-grade, deterministic compliance auditing engine designed to validate, trace, and remediate customer account deletion requests across distributed microservice topologies.

Built to satisfy strict GDPR/CCPA erasure mandates, platform-specific data retention laws (Rule 12), and topological ordering constraints, this engine operates with **zero runtime LLM calls** ($0.00 cost, zero hallucination risk), completing full-fleet audits over 518 production requests in under 80 seconds.

---

## Repo Link - https://github.com/pvnkmr205/northstar-compliance-engine

## AI Tooling & Multi-Agent Development Workflow

This project utilized a specialized multi-agent workflow where each AI model and coding harness was assigned a targeted operational domain, spanning architectural design, schema reverse-engineering, database ingestion, precise invariant patching, and evaluation packaging.

```
┌────────────────────────────────────────────────────────────────────────┐
│                     MULTI-AGENT WORKFLOW PIPELINE                      │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
   [ Argon / Gemini 4 ] ──► Architecture & 24h Roadmap Decomposition
                                    │
                                    ▼
   [ Antigravity / Gemini 3.8 Flash ] ──► Schema Reverse-Engineering & Digest
                                    │
                                    ▼
   [ GitHub Copilot / GPT-4o ] ──► Zero-Token SQLite Ingestion & BFS Identity
                                    │
                                    ▼
   [ OpenAI Codex / GPT-6 Luna ] ──► Invariant Surgery & Topological Sorter
                                    │
                                    ▼
   [ Gemini CLI / Gemini 2.5 Pro ] ──► Worker Correlator, Rule 12 & Packaging
```

### Tool & Model Allocation

| Tool / Harness | Model | Stage | Specific Tasks & Deliverables |
| :--- | :--- | :--- | :--- |
| **Argon** | `gemini-4-argon` | **Architecture & Roadmap** | Decomposed the hackathon problem statement into an hour-by-hour roadmap; formalized the 15 allowed platform operations and telemetry specifications. |
| **Antigravity** | `gemini-3.8-flash` | **Schema Analysis** | Parsed heterogeneous database dumps and sample output baselines into an ultra-compact schema digest (`context_bridge/schema_digest.md`) to avoid token waste. |
| **GitHub Copilot** | `copilot-gpt-4o` | **Data Ingestion** | Implemented `init_database()` to ingest 134 tables into local SQLite (`cache/northstar.db`) and scaffolded BFS identity traversal for `user_identities`. |
| **OpenAI Codex** | `gpt-6-luna` | **Invariant Auditing & Patching** | Performed targeted code modifications to fix 376 invariant defects: corrected operation name typos (`DISABLE_DATA_FLOW` → `DISABLE_FLOW`, `REDACT_RECORD` → `ANONYMIZE_RECORD`) and built the topological verification sorter. |
| **Gemini CLI** | `gemini-2.5-pro` | **Diagnostics, Compliance & Packaging** | Resolved the synthetic account ID fallback via `system_activity` worker logs, codified Rule 12 compliance preservation, authored formal evaluation reports with 3 adversarial cases, and assembled the final submission archive (`code.zip`). |

---

## Performance & Audit Benchmarks

| Metric | Target Specification | Achieved Performance |
|---|---|---|
| Sample Benchmark Accuracy | Ground-truth alignment | **100.00%** (32/32 cases; 0 status errors, 0 step errors) |
| Production Invariant Conformance | 0 violations across 518 cases | **100.00%** (518/518 cases; 0 schema, operation, or sequence errors) |
| Runtime Token Consumption | Cost-effective / constrained | **0 tokens** ($0.00 runtime LLM API costs) |
| Full Production Run Latency | Fleet processing under SLA | **79.20 seconds** (~152.9 ms per case) |
| Throughput | High-performance batching | **~6.54 cases / second** |
| Memory Footprint | Local embedded cache | **~35 MB RSS** (`cache/northstar.db` ~25 MB) |

---

## Production Audit Results (518 Cases)

Execution against `dataset/deletion_requests.csv` yields the following distribution in `output.csv`:

| Deletion Status | Count | Percentage | Compliance Definition |
|---|---:|---:|---|
| `COMPLETE` | 67 | 12.93% | Account deletion was fully propagated across all downstream systems. No residual personal data, active integrations, or restore permissions exist at `audit_at`. |
| `INCOMPLETE` | 399 | 77.03% | Residual records, exposed unhashed PII, active sync bridges, or unblocked backup archives were identified. A complete 3-phase remediation plan was generated. |
| `NOT_APPLICABLE` | 52 | 10.04% | The request text does not represent a valid permanent account deletion request (e.g., inquiry, data export request, marketing preference update). Returns an empty step list `[]`. |
| **Total** | **518** | **100.00%** | **100% invariant compliant** |

---

## System Architecture

<img width="2584" height="1458" alt="image" src="https://github.com/user-attachments/assets/a1f3bd80-5da5-4f12-aa61-55efee7bf11f" />


---

## Core Engineering Highlights

### 1. Zero-Token Deterministic Runtime

Rather than delegating high-stakes legal compliance reasoning to non-deterministic LLMs, the engine uses:

- **Embedded SQLite indexing** for millisecond-grade graph queries.
- **Regular expression state machines** to ingest unstructured event traces and shift handovers.
- **Windowed temporal correlation** (`requested_at ≤ event_time ≤ reported_at`) to identify primary accounts submitted by deletion workers.

### 2. Multi-Source Evidence Indexing (`evidence_indexer.py`)

Unifies disconnected enterprise data silos into the `evidence_records` relational store:

- **SQL Read-Replicas** (`evidence_05`): Ingests database dumps, extracting subject references and retention markers from raw `INSERT` statements.
- **Service Export Bundles** (`evidence_92`, `evidence_51`): Recursively traverses nested JSON trees to locate profile lookups, backup entries, and connector statuses.
- **Text Shift Handovers** (`evidence_03`): Parses pipe-delimited operational handover logs to correlate 404/not-found statuses with specific customer email aliases.
- **Anonymized Analytics Correlation**: Links decoupled, cohort-only analytics profiles back to requesting users via activity timestamps and IP/session metadata.

### 3. Legal Retention Preservation (Rule 12)

Under regulatory requirements (e.g., GDPR Art. 17(3)(b) legal defense obligations), audit records in `security_service` must never be deleted:

- The engine guarantees `security_service` records are **never** flagged as `REPORT_REMAINING_RECORD` or targeted with `DELETE_RECORD`.
- All valid audit records are verified as `VERIFY_RECORD_PRESENT` with `state="PRESENT"`.

### 4. Canonical Topological Verification Ordering

Downstream systems cannot be verified arbitrarily. The engine enforces a strict topological precedence matrix across all generated verification plans:

```
account_service → search_service → security_service → support_platform → identity_service
→ analytics_platform → integration_service → backup_service → export_service
```

| Precedence Rank | System Identifier | System Function & Scope |
|:---:|---|---|
| 1 | `account_service` | Primary profile registry (root system) |
| 2 | `search_service` | Downstream search indices and query caches |
| 3 | `security_service` | Mandatory compliance & audit log retention (Rule 12) |
| 4 | `support_platform` | Customer support tickets, transcripts, attachments |
| 5 | `identity_service` | Auth providers, credentials, tombstone records |
| 6 | `analytics_platform` | Behavior telemetry, cohorts, de-identification |
| 7 | `integration_service` | Event pipes, webhooks, third-party connectors |
| 8 | `backup_service` | Disaster recovery archives, restore permission locks |
| 9 | `export_service` | Ephemeral user data dumps, export zip staging |

---

## Allowed Operations Registry

The compliance engine restricts all outputs to the 15 approved platform operations:

| Phase | Allowed Operation | Valid Target State | Description |
|---|---|---|---|
| FINDING | `REPORT_REMAINING_RECORD` | `PRESENT` | Detects lingering personal records post-deletion |
| FINDING | `REPORT_EXPOSED_PII` | `PRESENT` | Identifies unmasked/unhashed identifiers |
| FINDING | `REPORT_ACTIVE_DATA_FLOW` | `ACTIVE` | Identifies live sync pipelines still pumping data |
| FINDING | `REPORT_RESTORE_RISK` | `ACTIVE` | Identifies backup archives with restore permissions enabled |
| REMEDIATION | `DELETE_RECORD` | `ABSENT` | Action to purge residual downstream records |
| REMEDIATION | `ANONYMIZE_RECORD` | `ANONYMIZED` | Action to scrub PII from retained profiles/tombstones |
| REMEDIATION | `DISABLE_FLOW` | `DISABLED` | Action to disconnect active integration bridges |
| REMEDIATION | `BLOCK_RESTORE` | `BLOCKED` | Action to flip archive restore permissions to false |
| VERIFICATION | `VERIFY_RECORD_ABSENT` | `ABSENT` | Confirms target record has been completely purged |
| VERIFICATION | `VERIFY_RECORD_PRESENT` | `PRESENT` | Confirms legally protected audit logs are intact (Rule 12) |
| VERIFICATION | `VERIFY_RECORD_ANONYMIZED` | `ANONYMIZED` | Confirms identifying fields have been neutralized |
| VERIFICATION | `VERIFY_RECORD_REDACTED` | `REDACTED` | Confirms partial masking of sensitive communication fields |
| VERIFICATION | `VERIFY_FLOW_DISABLED` | `DISABLED` | Confirms data integration pipe has stopped delivering |
| VERIFICATION | `VERIFY_RESTORE_BLOCKED` | `BLOCKED` | Confirms archive cannot be resurrected during DR |
| VERIFICATION | `VERIFY_TOMBSTONE_CREATED` | `TOMBSTONE` | Confirms terminal deletion marker has been registered |

---

## Repository Structure

```
hackerrank-orchestrate-october26/
├── run.py                           # Standard submission entry point (executes full audit)
├── output.csv                       # Complete 518-case production audit output
├── requirements.txt                 # Dependency specification (standard library native)
├── README.md                        # System architecture & operational manual
├── code.zip                         # Sanitized submission package for automated graders
│
├── src/
│   ├── __init__.py                  # Package marker
│   ├── pipeline.py                  # Identity graph resolution, audit rules, step sequencing
│   └── evidence_indexer.py          # Multi-format evidence parser (.log, .sql, .json, .txt)
│
├── evaluation/
│   ├── evaluation_report.md         # Quality, accuracy, and status report
│   └── usage_report.md              # Telemetry, performance, and resource consumption audit
│
├── dataset/                         # Benchmark requests, sample ground-truth, evidence data
│   ├── deletion_requests.csv        # 518 production customer deletion requests
│   ├── sample_deletion_requests.csv # 32 sample benchmark requests
│   ├── sample_output.csv            # 32-case ground-truth validation baseline
│   ├── evidence_files.csv           # File manifest and capture timestamps
│   └── evidence/                    # Raw databases, snapshot bundles, logs, and exports
│
├── run_full_evaluation.py           # Full production test runner
├── audit_production_output.py       # Production invariant & schema validation suite
└── diagnose_samples.py              # 32-case ground-truth differential diagnostics
```

---

## Quickstart & Execution

### Prerequisites

- Python 3.10 or higher
- Zero mandatory third-party runtime dependencies (operates natively using the standard library: `sqlite3`, `json`, `csv`, `pathlib`, `re`, `datetime`)

### 1. Run the Full Audit Pipeline

Execute the full audit across all 518 production requests to regenerate `output.csv`:

```bash
python run.py
```

### 2. Verify Invariant Compliance

Run the production audit suite to verify zero schema flaws, zero illegal operations, and strict topological ordering:

```bash
python audit_production_output.py
```

Expected output:

```text
=== AUDIT RESULTS ===
Total Cases Checked: 518
Total Invariant Issues Found: 0

ALL INVARIANTS SATISFIED: Zero schema errors, zero sequence flaws, zero illegal operations.
```

### 3. Verify Ground-Truth Sample Benchmark

Verify exact alignment against the 32 sample benchmark cases:

```bash
python diagnose_samples.py
```

Expected output:

```text
Total: 32 | Passed: 32 | Status Fails: 0 | Step Fails: 0
```

---

## Verification & Remediation Lifecycle Examples

### Case Type A: `COMPLETE` (Clean Deletion)

For cases where deletion succeeded across the board, only a `VERIFICATION` phase is emitted, sorted by system precedence:

```json
[
  {"step_no": 1, "phase": "VERIFICATION", "system_id": "account_service", "resource_id": "account_7566", "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": "evidence_94"},
  {"step_no": 2, "phase": "VERIFICATION", "system_id": "security_service", "resource_id": "audit_record_2016", "operation": "VERIFY_RECORD_PRESENT", "state": "PRESENT", "evidence_id": "evidence_94"},
  {"step_no": 3, "phase": "VERIFICATION", "system_id": "analytics_platform", "resource_id": "analytics_9406", "operation": "VERIFY_RECORD_ANONYMIZED", "state": "ANONYMIZED", "evidence_id": "evidence_94"}
]
```

### Case Type B: `INCOMPLETE` (Downstream Leaks Remediated)

For cases where residual records were detected, the engine emits a 3-phase plan (FINDING → REMEDIATION → VERIFICATION):

```json
[
  {"step_no": 1, "phase": "FINDING", "system_id": "support_platform", "resource_id": "support_001", "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": "evidence_58"},
  {"step_no": 2, "phase": "REMEDIATION", "system_id": "support_platform", "resource_id": "support_001", "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": ""},
  {"step_no": 3, "phase": "VERIFICATION", "system_id": "account_service", "resource_id": "account_007", "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": ""},
  {"step_no": 4, "phase": "VERIFICATION", "system_id": "support_platform", "resource_id": "support_001", "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": ""}
]
```

---

## Packaging & Deliverables

To package the workspace for submission while stripping non-essential debug traces and cache databases:

```powershell
python -c "import zipfile, pathlib; z=zipfile.ZipFile('code.zip','w',zipfile.ZIP_DEFLATED); [z.write(f,f) for f in ['run.py','output.csv','README.md','requirements.txt','audit_production_output.py','diagnose_samples.py']]; [z.write(p,p) for d in ['src','evaluation'] for p in pathlib.Path(d).rglob('*') if p.is_file() and not any(x in p.parts for x in ['__pycache__','.git','cache'])]; print('code.zip generated successfully.')"
```

The resulting `code.zip` (< 200 KB) contains all required entry points, source implementations, evaluation documentation, and the final production `output.csv`.
