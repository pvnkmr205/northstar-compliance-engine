# Northstar Privacy Compliance Audit — Evaluation Report

## 1. Executive Summary & Accuracy Benchmarks
- **Dataset Evaluated:** `dataset/deletion_requests.csv` (518 production cases)
- **Sample Benchmark Pass Rate:** 100.00% (32/32 cases)
  - Status Accuracy: 100.00% (32/32)
  - Step-Level Operation Accuracy: 100.00%
  - Field-Level Invariant Accuracy: 100.00%
  - Sequence Accuracy: 100.00% (topological order strictly preserved)
- **Production Fleet Invariant Violations:** 0 schema errors, 0 illegal operations, 0 topological flaws across all 518 cases.
- **Production Status Distribution:**
  - COMPLETE: 67 (12.93%)
  - INCOMPLETE: 399 (77.03%)
  - NOT_APPLICABLE: 52 (10.04%)
- **Total Audit Steps Generated:** 2,429 steps (mean: 4.69 steps/case)

## 2. Participant-Constructed Evaluation Cases
As required by the project contract, three adversarial test cases were designed and verified against the compliance engine:

### Case A: `custom_case_01` — Active Sync Race Condition with Rule 12 Retention
- **Scenario:** A customer with alias `j.doe_alt@corp.com` requests deletion. Primary account `account_9011` was deleted, but an active connector `data_flow_41` in `integration_service` is syncing records back to reporting replicas. Meanwhile, a mandatory audit record `audit_record_991` exists in `security_service`.
- **Expected Outcome:** `INCOMPLETE`.
- **Action Plan:**
  1. FINDING: `REPORT_ACTIVE_DATA_FLOW` on `data_flow_41` (`integration_service`).
  2. REMEDIATION: `DISABLE_FLOW` on `data_flow_41`.
  3. VERIFICATION (Topological):
     - `account_service`: `account_9011` (`VERIFY_RECORD_ABSENT`)
     - `security_service`: `audit_record_991` (`VERIFY_RECORD_PRESENT`) [Rule 12]
     - `integration_service`: `data_flow_41` (`VERIFY_FLOW_DISABLED`)
- **Engine Verification:** Passed. Correctly distinguished between illegal remaining data and legal audit retention.

### Case B: `custom_case_02` — Non-Deletion Data Portability Request
- **Scenario:** Customer submits: *"Please send me a full zip export of all my personal data and recent invoices under GDPR Article 20."*
- **Expected Outcome:** `NOT_APPLICABLE`.
- **Engine Verification:** Passed. Correctly classified as an access/export request rather than account erasure, emitting status `NOT_APPLICABLE` and empty steps array `[]`.

### Case C: `custom_case_03` — Stale Disaster Recovery Restore Risk
- **Scenario:** Primary account and search indices scrubbed. However, snapshot `backup_archive_883` in `backup_service` has `restore_allowed: true` with direct user identifiers present.
- **Expected Outcome:** `INCOMPLETE`.
- **Action Plan:**
  1. FINDING: `REPORT_RESTORE_RISK` on `backup_archive_883` (`backup_service`).
  2. REMEDIATION: `BLOCK_RESTORE` on `backup_archive_883`.
  3. VERIFICATION:
     - `account_service`: `account_102` (`VERIFY_RECORD_ABSENT`)
     - `backup_service`: `backup_archive_883` (`VERIFY_RESTORE_BLOCKED`)
- **Engine Verification:** Passed. Precedence verified with root account checked before backup verification.

## 3. Failures Identified & Engineering Improvements
During development and benchmarking, the engine underwent four major architectural iterations:

1. **Synthetic Account Fallback Failure:**
   - *Failure:* The pipeline originally synthesized primary account IDs (e.g., `user_21` -> `account_021`), causing step mismatches against ground truth.
   - *Resolution:* Ingested `system_activity` worker logs to correlate actual primary account IDs (`account_6440`, `account_3136`) matched within temporal windows (`requested_at` to `reported_at`).
2. **Missing Security Audit Evidence in SQL Replicas:**
   - *Failure:* Unindexed `INSERT` statements in SQL replica dumps caused audit records (`audit_record_9528`) to appear absent.
   - *Resolution:* Implemented regex ingestion in `evidence_indexer.py` targeting `customer_data_read_replica` and JSON snapshot bundles, correctly preserving Rule 12 retention.
3. **Disallowed Operation Naming Typos:**
   - *Failure:* Production audit revealed illegal operation names (`DISABLE_DATA_FLOW`, `VERIFY_DATA_FLOW_DISABLED`, `REDACT_RECORD`).
   - *Resolution:* Strictly bound output mappings to the 15 allowed platform operations (`DISABLE_FLOW`, `VERIFY_FLOW_DISABLED`, `ANONYMIZE_RECORD`).
4. **Topological Inversion in Verification Plans:**
   - *Failure:* Retained audit records were being appended at the end of the verification list, violating system precedence.
   - *Resolution:* Added `canonical_sort_and_number` enforcing the strict topological ranking (ranks 1 through 9).
