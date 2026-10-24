import csv
import json
import time
from pathlib import Path
from src.pipeline import init_database, resolve_identity, audit_case, build_steps_json

t0 = time.time()
conn = init_database()

input_csv = Path("dataset/deletion_requests.csv")
output_csv = Path("output.csv")

if not input_csv.exists():
    print(f"Error: {input_csv} not found!")
    exit(1)

with open(input_csv, encoding="utf-8-sig") as f:
    requests = list(csv.DictReader(f))

print(f"Starting audit for {len(requests)} production cases...")

results = []
status_counts = {"COMPLETE": 0, "INCOMPLETE": 0, "NOT_APPLICABLE": 0}

for i, req in enumerate(requests, 1):
    cid = req.get("case_id") or f"case_{i:03d}"
    email = req.get("email", "")
    
    identity = resolve_identity(email, conn)
    status, steps = audit_case(req, identity, conn)
    steps_json = build_steps_json(status, steps)
    
    status_counts[status] = status_counts.get(status, 0) + 1
    results.append({
        "case_id": cid,
        "deletion_status": status,
        "steps_json": steps_json
    })

conn.close()

# Write output.csv with exact UTF-8 formatting and standard csv quoting
with open(output_csv, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=["case_id", "deletion_status", "steps_json"])
    writer.writeheader()
    writer.writerows(results)

elapsed = time.time() - t0
print(f"\nDone in {elapsed:.2f}s ({elapsed/len(requests)*1000:.1f}ms/case)")
print(f"Total Cases: {len(results)}")
print(f"Status Breakdown: {status_counts}")
print(f"Saved: {output_csv.resolve()}")
