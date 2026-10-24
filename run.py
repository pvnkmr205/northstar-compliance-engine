"""
Standard Hackathon Submission Entry Point
Executes the full end-to-end privacy audit pipeline on dataset/deletion_requests.csv
and outputs output.csv.
"""
import sys
import time
from pathlib import Path

# Ensure repo root is in sys.path
sys.path.insert(0, str(Path(__file__).parent))

if __name__ == "__main__":
    t0 = time.time()
    print("=" * 60)
    print("NORTHSTAR PRIVACY COMPLIANCE AUDIT ENGINE")
    print("=" * 60)

    # Execute production audit pipeline
    import run_full_evaluation

    print(f"\nExecution finished in {time.time() - t0:.2f} seconds.")
