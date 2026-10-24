import csv
import json
from src.pipeline import init_database, resolve_identity, audit_case, build_steps_json

conn = init_database()
with open("dataset/sample_deletion_requests.csv", encoding="utf-8-sig") as f:
    samples = list(csv.DictReader(f))
with open("dataset/sample_output.csv", encoding="utf-8-sig") as f:
    expected = {r["case_id"]: r for r in csv.DictReader(f)}

status_fails = []
step_fails = []
passes = []

for c in samples:
    cid = c["case_id"]
    exp = expected[cid]
    identity = resolve_identity(c["email"], conn)
    act_status, act_steps = audit_case(c, identity, conn)
    act_json = build_steps_json(act_status, act_steps)

    if act_status != exp["deletion_status"]:
        status_fails.append((cid, exp["deletion_status"], act_status, c["request_text"]))
    else:
        try:
            if json.loads(act_json) == json.loads(exp["steps_json"]):
                passes.append(cid)
            else:
                step_fails.append((cid, exp["steps_json"], act_json))
        except Exception:
            step_fails.append((cid, exp["steps_json"], act_json))

print(f"Total: {len(samples)} | Passed: {len(passes)} | Status Fails: {len(status_fails)} | Step Fails: {len(step_fails)}")

print("\n=== STATUS MISMATCHES (First 5) ===")
for cid, exp_s, act_s, txt in status_fails[:5]:
    print(f"[{cid}] Expected: {exp_s} | Got: {act_s}")
    print(f"       Text: {txt[:100]}...")

print("\n=== STEP MISMATCHES (First 3) ===")
for cid, exp_j, act_j in step_fails[:3]:
    print(f"[{cid}]")
    print(f"  Expected: {exp_j}")
    print(f"  Actual:   {act_j}")

conn.close()
