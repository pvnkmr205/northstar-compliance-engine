import csv
import json
import re

ALLOWED_OPERATIONS = {
    "FINDING": ["REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII", "REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK"],
    "REMEDIATION": ["DELETE_RECORD", "ANONYMIZE_RECORD", "DISABLE_FLOW", "BLOCK_RESTORE"],
    "VERIFICATION": [
        "VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT", "VERIFY_RECORD_ANONYMIZED", 
        "VERIFY_RECORD_REDACTED", "VERIFY_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED", "VERIFY_TOMBSTONE_CREATED"
    ]
}

SYSTEM_ORDER = {
    "account_service": 1,
    "search_service": 2,
    "security_service": 3,
    "support_platform": 4,
    "identity_service": 5,
    "analytics_platform": 6,
    "integration_service": 7,
    "backup_service": 8,
    "export_service": 9
}

issues = []

with open("output.csv", encoding="utf-8") as f:
    rows = list(csv.DictReader(f))

if len(rows) != 518:
    issues.append(f"Row count mismatch: expected 518, got {len(rows)}")

for idx, row in enumerate(rows, 1):
    cid = row.get("case_id", f"row_{idx}")
    status = row.get("deletion_status", "")
    raw_json = row.get("steps_json", "")

    # 1. Status check
    if status not in ["COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"]:
        issues.append(f"[{cid}] Invalid status: {status}")
        continue

    try:
        steps = json.loads(raw_json)
    except Exception as e:
        issues.append(f"[{cid}] Malformed JSON: {e}")
        continue

    if status == "NOT_APPLICABLE":
        if len(steps) != 0:
            issues.append(f"[{cid}] NOT_APPLICABLE must have empty steps_json, got {len(steps)} steps")
        continue

    if len(steps) == 0:
        issues.append(f"[{cid}] {status} case has empty steps_json")
        continue

    # 2. Sequential step numbering
    for i, step in enumerate(steps, 1):
        if step.get("step_no") != i:
            issues.append(f"[{cid}] Non-continuous step_no: expected {i}, got {step.get('step_no')}")
            break

    # 3. Phase sequence & allowed operations
    phases = [s.get("phase") for s in steps]
    seen_phase_order = []
    for p in phases:
        if not seen_phase_order or seen_phase_order[-1] != p:
            seen_phase_order.append(p)

    if status == "COMPLETE":
        if seen_phase_order != ["VERIFICATION"]:
            issues.append(f"[{cid}] COMPLETE case has invalid phases: {seen_phase_order}")
    elif status == "INCOMPLETE":
        if seen_phase_order not in [["FINDING", "REMEDIATION", "VERIFICATION"], ["FINDING", "VERIFICATION"]]:
            issues.append(f"[{cid}] INCOMPLETE case has invalid phases: {seen_phase_order}")

    for step in steps:
        p = step.get("phase")
        op = step.get("operation")
        sys_id = step.get("system_id")
        res_id = step.get("resource_id", "")
        ev_id = step.get("evidence_id", "")
        state = step.get("state")

        # Allowed op check
        if op not in ALLOWED_OPERATIONS.get(p, []):
            issues.append(f"[{cid}] Operation '{op}' illegal in phase '{p}'")

        # Null or placeholder checks
        if not res_id or "None" in res_id or "null" in res_id:
            issues.append(f"[{cid}] Invalid resource_id: '{res_id}'")

        # Rule 12 Check: Security service audit records must NEVER be deleted
        if sys_id == "security_service" and op in ["DELETE_RECORD", "REPORT_REMAINING_RECORD"]:
            issues.append(f"[{cid}] Rule 12 Violation: audit record targeted for deletion: {res_id}")

        # Remediation evidence_id check: must be empty string
        if p == "REMEDIATION" and ev_id != "":
            issues.append(f"[{cid}] REMEDIATION step has non-empty evidence_id: '{ev_id}'")

    # 4. Topological sort order in VERIFICATION phase
    verif_steps = [s for s in steps if s.get("phase") == "VERIFICATION"]
    verif_ranks = [SYSTEM_ORDER.get(s.get("system_id"), 99) for s in verif_steps]
    if verif_ranks != sorted(verif_ranks):
        systems = [s.get("system_id") for s in verif_steps]
        issues.append(f"[{cid}] Verification system ordering violation: {systems}")

print(f"=== AUDIT RESULTS ===")
print(f"Total Cases Checked: {len(rows)}")
print(f"Total Invariant Issues Found: {len(issues)}")
if issues:
    print("\nFirst 10 Issues:")
    for iss in issues[:10]:
        print(f" - {iss}")
else:
    print("\nALL INVARIANTS SATISFIED: Zero schema errors, zero sequence flaws, zero illegal operations.")
