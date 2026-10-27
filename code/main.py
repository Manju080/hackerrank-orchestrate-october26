"""main.py - Production Entry Point for Ghost Data Still Exists Deletion-Audit Agent.

Executes the complete audit pipeline against dataset/deletion_requests.csv and
generates the official root-level output.csv conforming strictly to the challenge contract:
- Columns: case_id, deletion_status, steps_json
- Exactly 518 evaluation rows, sorted alphanumerically by case_id
- deletion_status: COMPLETE | INCOMPLETE | NOT_APPLICABLE
- steps_json: Valid JSON array of 7-key step objects
- Deterministic execution and JSON serialization
"""

import sys
import argparse
import json
from pathlib import Path
from typing import Dict, List, Any
import pandas as pd

# Add repository root to sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from code.config import (
    DELETION_REQUESTS_PATH,
    OUTPUT_CSV_PATH,
    ALLOWED_STATUSES,
    ALLOWED_PHASES,
    OPERATION_STATE_MAPPING,
    STEP_KEYS,
)
from code.audit.pipeline import AuditPipeline


def generate_deletion_audit_output(
    input_path: Path = DELETION_REQUESTS_PATH,
    output_path: Path = OUTPUT_CSV_PATH,
) -> pd.DataFrame:
    """Run full production pipeline on input requests and save output.csv."""
    print(f"Loading deletion requests from: {input_path}")
    df_req = pd.read_csv(input_path)
    total_cases = len(df_req)
    print(f"Total requests to process: {total_cases}")

    # Initialize shared production pipeline
    pipeline = AuditPipeline()

    results = []
    print("Executing audit pipeline across all requests...")

    for idx, row in df_req.iterrows():
        case_id = str(row["case_id"]).strip()
        status, steps = pipeline.audit_case(row)

        # Enforce NOT_APPLICABLE steps_json = []
        if status == "NOT_APPLICABLE":
            steps = []

        # Validate step consecutive numbering
        for step_idx, step in enumerate(steps, start=1):
            step["step_no"] = step_idx

        # Serialize steps_json deterministically
        steps_json = json.dumps(steps, separators=(",", ":"))
        results.append({
            "case_id": case_id,
            "deletion_status": status,
            "steps_json": steps_json,
        })

        if (idx + 1) % 50 == 0 or (idx + 1) == total_cases:
            print(f"  Processed {idx + 1}/{total_cases} requests ({(idx + 1)/total_cases*100:.1f}%)")

    df_out = pd.DataFrame(results)

    # Sort alphanumerically by case_id (e.g. case_01, case_02, ... case_550)
    def case_sort_key(cid: str):
        parts = cid.split("_")
        if len(parts) == 2 and parts[1].isdigit():
            return (parts[0], int(parts[1]))
        return (cid, 0)

    df_out["sort_key"] = df_out["case_id"].apply(case_sort_key)
    df_out = df_out.sort_values(by="sort_key").drop(columns=["sort_key"]).reset_index(drop=True)

    # Write output.csv to specified location
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df_out.to_csv(output_path, index=False, encoding="utf-8", lineterminator="\n")
    print(f"\nSuccessfully wrote {len(df_out)} predictions to: {output_path}")

    return df_out


def validate_output_csv(output_path: Path = OUTPUT_CSV_PATH, expected_count: int = 518) -> bool:
    """Validate output.csv structure, schema, consecutive numbering, and data integrity."""
    print(f"\nValidating output file: {output_path}")
    if not output_path.exists():
        print(f"ERROR: Output file does not exist: {output_path}")
        return False

    df = pd.read_csv(output_path)

    # 1. Row count check
    if len(df) != expected_count:
        print(f"ERROR: Expected {expected_count} rows, got {len(df)}")
        return False
    print(f"  [PASS] Row count matches expected: {len(df)} rows")

    # 2. Header and column order check
    expected_cols = ["case_id", "deletion_status", "steps_json"]
    if list(df.columns) != expected_cols:
        print(f"ERROR: Expected columns {expected_cols}, got {list(df.columns)}")
        return False
    print(f"  [PASS] Header matches exact schema: {list(df.columns)}")

    # 3. Duplicate and missing case_ids check
    if df["case_id"].duplicated().any():
        dupes = df[df["case_id"].duplicated()]["case_id"].tolist()
        print(f"ERROR: Duplicate case_ids found: {dupes}")
        return False
    print(f"  [PASS] No duplicate case_ids found ({len(df['case_id'].unique())} unique)")

    # 4. Content schema and validity check
    for idx, row in df.iterrows():
        cid = row["case_id"]
        status = row["deletion_status"]
        steps_raw = row["steps_json"]

        if status not in ALLOWED_STATUSES:
            print(f"ERROR: Invalid deletion_status '{status}' in {cid}")
            return False

        try:
            steps = json.loads(steps_raw)
        except Exception as e:
            print(f"ERROR: Invalid JSON in {cid}: {e}")
            return False

        if not isinstance(steps, list):
            print(f"ERROR: steps_json is not an array in {cid}")
            return False

        if status == "NOT_APPLICABLE" and len(steps) != 0:
            print(f"ERROR: NOT_APPLICABLE case {cid} has non-empty steps")
            return False

        current_phase_idx = 0
        phase_order = {"FINDING": 1, "REMEDIATION": 2, "VERIFICATION": 3}

        for step_idx, step in enumerate(steps, start=1):
            if list(step.keys()) != STEP_KEYS:
                print(f"ERROR: Step keys mismatch in {cid} step {step_idx}: {list(step.keys())}")
                return False

            if step["step_no"] != step_idx:
                print(f"ERROR: Step numbering not consecutive in {cid}: got {step['step_no']}, expected {step_idx}")
                return False

            phase = step["phase"]
            op = step["operation"]
            state = step["state"]
            ev_id = step["evidence_id"]

            if phase not in ALLOWED_PHASES:
                print(f"ERROR: Invalid phase '{phase}' in {cid}")
                return False

            p_idx = phase_order.get(phase, 0)
            if p_idx < current_phase_idx:
                print(f"ERROR: Phase ordering violation in {cid}: {phase} after earlier higher phase")
                return False
            current_phase_idx = p_idx

            if op not in OPERATION_STATE_MAPPING:
                print(f"ERROR: Invalid operation '{op}' in {cid}")
                return False

            if state != OPERATION_STATE_MAPPING[op]:
                print(f"ERROR: Invalid state '{state}' for op '{op}' in {cid}")
                return False

            # Incomplete post-remediation steps must have empty evidence_id
            if status == "INCOMPLETE" and phase in ["REMEDIATION", "VERIFICATION"]:
                if ev_id != "":
                    print(f"ERROR: Non-empty evidence_id '{ev_id}' in future {phase} step of {cid}")
                    return False

    print("  [PASS] All 518 cases satisfy schema, ordering, and evidence contract")
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ghost Data Still Exists Deletion-Audit Agent")
    parser.add_argument("--input", type=str, default=str(DELETION_REQUESTS_PATH), help="Input requests CSV path")
    parser.add_argument("--output", type=str, default=str(OUTPUT_CSV_PATH), help="Output predictions CSV path")
    parser.add_argument("--validate-only", action="store_true", help="Only validate existing output CSV")

    args = parser.parse_args()

    out_file = Path(args.output)
    if args.validate_only:
        valid = validate_output_csv(out_file)
        sys.exit(0 if valid else 1)

    generate_deletion_audit_output(Path(args.input), out_file)
    valid = validate_output_csv(out_file)
    if not valid:
        print("ERROR: Final validation failed.")
        sys.exit(1)
    print("\nPhase 5 Generation & Validation Complete!")
