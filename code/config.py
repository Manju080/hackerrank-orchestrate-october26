"""Configuration and official contract definitions for Ghost Data Still Exists.

All paths are resolved relative to the repository root.
"""

from pathlib import Path
from typing import Dict, List, Set

# Central Repository Paths
REPO_ROOT: Path = Path(__file__).resolve().parent.parent
DATASET_DIR: Path = REPO_ROOT / "dataset"
EVIDENCE_DIR: Path = DATASET_DIR / "evidence"
PROMPTS_DIR: Path = REPO_ROOT / "code" / "prompts"
EVALUATION_DIR: Path = REPO_ROOT / "code" / "evaluation"
OUTPUT_CSV_PATH: Path = REPO_ROOT / "output.csv"

# Participant-Facing Dataset Paths
DELETION_REQUESTS_PATH: Path = DATASET_DIR / "deletion_requests.csv"
SAMPLE_DELETION_REQUESTS_PATH: Path = DATASET_DIR / "sample_deletion_requests.csv"
SAMPLE_OUTPUT_PATH: Path = DATASET_DIR / "sample_output.csv"
USER_IDENTITIES_PATH: Path = DATASET_DIR / "user_identities.csv"
USER_AUDIT_LOG_PATH: Path = DATASET_DIR / "user_audit_log.csv"
SYSTEM_ACTIVITY_PATH: Path = DATASET_DIR / "system_activity.csv"
DELETION_RULES_PATH: Path = DATASET_DIR / "deletion_rules.csv"
EVIDENCE_FILES_PATH: Path = DATASET_DIR / "evidence_files.csv"

# Allowed Status Enums
STATUS_COMPLETE: str = "COMPLETE"
STATUS_INCOMPLETE: str = "INCOMPLETE"
STATUS_NOT_APPLICABLE: str = "NOT_APPLICABLE"
ALLOWED_STATUSES: Set[str] = {
    STATUS_COMPLETE,
    STATUS_INCOMPLETE,
    STATUS_NOT_APPLICABLE,
}

# Allowed Phase Enums & Canonical Ordering
PHASE_FINDING: str = "FINDING"
PHASE_REMEDIATION: str = "REMEDIATION"
PHASE_VERIFICATION: str = "VERIFICATION"
ALLOWED_PHASES: List[str] = [
    PHASE_FINDING,
    PHASE_REMEDIATION,
    PHASE_VERIFICATION,
]

# Allowed Operations and Their Strictly Mapped Required States
OPERATION_STATE_MAPPING: Dict[str, str] = {
    # FINDINGS
    "REPORT_REMAINING_RECORD": "PRESENT",
    "REPORT_EXPOSED_PII": "PRESENT",
    "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
    "REPORT_RESTORE_RISK": "ACTIVE",
    # REMEDIATION
    "DISABLE_DATA_FLOW": "DISABLED",
    "BLOCK_RESTORE": "BLOCKED",
    "DELETE_RECORD": "ABSENT",
    "REDACT_RECORD": "REDACTED",
    "ANONYMIZE_RECORD": "ANONYMIZED",
    # VERIFICATION
    "VERIFY_RECORD_ABSENT": "ABSENT",
    "VERIFY_RECORD_PRESENT": "PRESENT",
    "VERIFY_RECORD_REDACTED": "REDACTED",
    "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
    "VERIFY_RESTORE_BLOCKED": "BLOCKED",
}

# Canonical Operation Priority per Phase
CANONICAL_OPERATION_ORDER: Dict[str, List[str]] = {
    PHASE_FINDING: [
        "REPORT_REMAINING_RECORD",
        "REPORT_EXPOSED_PII",
        "REPORT_ACTIVE_DATA_FLOW",
        "REPORT_RESTORE_RISK",
    ],
    PHASE_REMEDIATION: [
        "DISABLE_DATA_FLOW",
        "BLOCK_RESTORE",
        "DELETE_RECORD",
        "REDACT_RECORD",
        "ANONYMIZE_RECORD",
    ],
    PHASE_VERIFICATION: [
        "VERIFY_RECORD_ABSENT",
        "VERIFY_RECORD_PRESENT",
        "VERIFY_RECORD_REDACTED",
        "VERIFY_RECORD_ANONYMIZED",
        "VERIFY_DATA_FLOW_DISABLED",
        "VERIFY_RESTORE_BLOCKED",
    ],
}

FINDING_OPERATION_ORDER: Dict[str, int] = {
    op: idx for idx, op in enumerate(CANONICAL_OPERATION_ORDER[PHASE_FINDING])
}
REMEDIATION_OPERATION_ORDER: Dict[str, int] = {
    op: idx for idx, op in enumerate(CANONICAL_OPERATION_ORDER[PHASE_REMEDIATION])
}
VERIFICATION_OPERATION_ORDER: Dict[str, int] = {
    op: idx for idx, op in enumerate(CANONICAL_OPERATION_ORDER[PHASE_VERIFICATION])
}

# Mandatory Step Keys
STEP_KEYS: List[str] = [
    "step_no",
    "phase",
    "system_id",
    "resource_id",
    "operation",
    "state",
    "evidence_id",
]

# Output CSV Columns
OUTPUT_COLUMNS: List[str] = [
    "case_id",
    "deletion_status",
    "steps_json",
]
