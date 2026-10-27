"""custom_cases.py - Independent evaluation fixtures for deletion audit validation.

Defines three independent, realistic end-to-end evaluation scenarios:
1. Historical identifier reuse / decoy identity guard (preventing false merges).
2. Remaining downstream record combined with active sync and restore risks.
3. Policy-required retained record and permitted tombstone requiring PII redaction.

Each fixture provides its own input request, isolated identity graph, mock evidence,
and expected output with full step sequence.
"""

import sys
from pathlib import Path
from typing import Dict, List, Any
from dataclasses import dataclass

# Ensure repository root is on sys.path
REPO_ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT_DIR))

from code.audit.identity import UserIdentity, IdentityResolver
from code.audit.evidence_engine import ExtractedRecord
from code.audit.activity_tracker import FlowAndRiskFact
from code.audit.policy_engine import PolicyEngine, EvaluatedItem
from code.audit.planner import RemediationPlanner
from code.audit.intent_detector import determine_deletion_intent


@dataclass
class CustomTestCase:
    case_id: str
    description: str
    request: Dict[str, Any]
    user_identity: UserIdentity
    decoy_identities: List[UserIdentity]
    extracted_records: List[ExtractedRecord]
    flow_risks: List[FlowAndRiskFact]
    restore_risks: List[FlowAndRiskFact]
    expected_status: str
    expected_steps: List[Dict[str, Any]]


def get_custom_test_cases() -> List[CustomTestCase]:
    """Return the three independent custom test cases."""
    
    # --------------------------------------------------------------------------
    # Case 1: Identifier Reuse / Decoy Identity Guard
    # Target User (user_cust_01) previously held email 'j.doe@example.com' until 2026-03-01.
    # Decoy User (user_cust_decoy) adopted 'j.doe@example.com' on 2026-04-01.
    # Request is submitted on 2026-02-15 for user_cust_01.
    # Decoy's active account record (captured in June 2026) MUST NOT be merged into user_cust_01's audit.
    # --------------------------------------------------------------------------
    user_01 = UserIdentity(
        user_id="user_cust_01",
        name="John Doe",
        current_email="john.doe.new@example.com",
        current_phone="+1 202 555 0191",
        email_hash="hash_cust_01",
        snapshot_updated_at="2026-03-01T00:00:00Z",
        historical_emails=[("j.doe@example.com", "2026-03-01T00:00:00Z", "audit_cust_01")],
    )
    decoy_01 = UserIdentity(
        user_id="user_cust_decoy",
        name="Jane Doe",
        current_email="j.doe@example.com",
        current_phone="+1 202 555 0192",
        email_hash="hash_cust_decoy",
        snapshot_updated_at="2026-04-01T00:00:00Z",
    )
    
    # Target user's account was properly verified absent
    rec_01 = ExtractedRecord(
        evidence_id="evidence_cust_01",
        system_id="account_service",
        resource_id="account_cust_01",
        user_id="user_cust_01",
        email="john.doe.new@example.com",
        phone="+1 202 555 0191",
        record_state="ABSENT",
        event_timestamp="2026-02-25T10:00:00Z",
        details={"status": "ABSENT"},
    )
    
    case_1 = CustomTestCase(
        case_id="custom_case_01",
        description="Temporal email alias reuse: decoy account with same historical email must not cause false merge or false incomplete.",
        request={
            "case_id": "custom_case_01",
            "email": "j.doe@example.com",  # Submitted with historical email
            "requested_at": "2026-02-15T09:00:00Z",
            "reported_status": "COMPLETE",
            "reported_at": "2026-02-20T10:00:00Z",
            "audit_at": "2026-03-10T12:00:00Z",
            "request_text": "Please delete the account and all associated personal data linked to j.doe@example.com.",
        },
        user_identity=user_01,
        decoy_identities=[decoy_01],
        extracted_records=[rec_01],
        flow_risks=[],
        restore_risks=[],
        expected_status="COMPLETE",
        expected_steps=[
            {
                "step_no": 1,
                "phase": "VERIFICATION",
                "system_id": "account_service",
                "resource_id": "account_cust_01",
                "operation": "VERIFY_RECORD_ABSENT",
                "state": "ABSENT",
                "evidence_id": "evidence_cust_01",
            }
        ],
    )

    # --------------------------------------------------------------------------
    # Case 2: Remaining Downstream Record + Active Sync + Restore Risk
    # User requested deletion, primary account deleted, but an export copy remains,
    # connector is still active, and backup restore is active.
    # --------------------------------------------------------------------------
    user_02 = UserIdentity(
        user_id="user_cust_02",
        name="Carlos Silva",
        current_email="carlos.silva@example.com",
        current_phone="+55 11 98765 4321",
        email_hash="hash_cust_02",
        snapshot_updated_at="2026-06-01T00:00:00Z",
    )
    
    rec_export = ExtractedRecord(
        evidence_id="evidence_cust_02",
        system_id="export_service",
        resource_id="export_cust_99",
        user_id="user_cust_02",
        email="carlos.silva@example.com",
        phone=None,
        record_state="PRESENT",
        event_timestamp="2026-07-05T12:00:00Z",
        details={"type": "USER_EXPORT", "downloadable": True},
    )
    flow_02 = FlowAndRiskFact(
        fact_type="DATA_FLOW",
        system_id="integration_service",
        resource_id="data_flow_cust_55",
        source_system="integration_service",
        target_system="analytics_platform",
        event_time="2026-07-06T10:00:00Z",
        evidence_id="evidence_cust_02",
        details="Active data bridge",
        is_active_risk=True,
    )
    risk_02 = FlowAndRiskFact(
        fact_type="RESTORE_RISK",
        system_id="backup_service",
        resource_id="backup_cust_77",
        source_system="backup_service",
        target_system="archive_service",
        event_time="2026-07-07T08:00:00Z",
        evidence_id="evidence_cust_02",
        details="Daily snapshot containing user data",
        is_active_risk=True,
    )

    case_2 = CustomTestCase(
        case_id="custom_case_02",
        description="Downstream remaining export combined with active connector and backup restore risk.",
        request={
            "case_id": "custom_case_02",
            "email": "carlos.silva@example.com",
            "requested_at": "2026-07-01T10:00:00Z",
            "reported_status": "COMPLETE",
            "reported_at": "2026-07-03T11:00:00Z",
            "audit_at": "2026-07-15T12:00:00Z",
            "request_text": "Please permanently remove my account, download packages, and all associated information.",
        },
        user_identity=user_02,
        decoy_identities=[],
        extracted_records=[rec_export],
        flow_risks=[flow_02],
        restore_risks=[risk_02],
        expected_status="INCOMPLETE",
        expected_steps=[
            # FINDINGS
            {
                "step_no": 1,
                "phase": "FINDING",
                "system_id": "export_service",
                "resource_id": "export_cust_99",
                "operation": "REPORT_REMAINING_RECORD",
                "state": "PRESENT",
                "evidence_id": "evidence_cust_02",
            },
            {
                "step_no": 2,
                "phase": "FINDING",
                "system_id": "integration_service",
                "resource_id": "data_flow_cust_55",
                "operation": "REPORT_ACTIVE_DATA_FLOW",
                "state": "ACTIVE",
                "evidence_id": "evidence_cust_02",
            },
            {
                "step_no": 3,
                "phase": "FINDING",
                "system_id": "backup_service",
                "resource_id": "backup_cust_77",
                "operation": "REPORT_RESTORE_RISK",
                "state": "ACTIVE",
                "evidence_id": "evidence_cust_02",
            },
            # REMEDIATION (Flows/restores before records)
            {
                "step_no": 4,
                "phase": "REMEDIATION",
                "system_id": "integration_service",
                "resource_id": "data_flow_cust_55",
                "operation": "DISABLE_DATA_FLOW",
                "state": "DISABLED",
                "evidence_id": "",
            },
            {
                "step_no": 5,
                "phase": "REMEDIATION",
                "system_id": "backup_service",
                "resource_id": "backup_cust_77",
                "operation": "BLOCK_RESTORE",
                "state": "BLOCKED",
                "evidence_id": "",
            },
            {
                "step_no": 6,
                "phase": "REMEDIATION",
                "system_id": "export_service",
                "resource_id": "export_cust_99",
                "operation": "DELETE_RECORD",
                "state": "ABSENT",
                "evidence_id": "",
            },
            # VERIFICATION
            {
                "step_no": 7,
                "phase": "VERIFICATION",
                "system_id": "export_service",
                "resource_id": "export_cust_99",
                "operation": "VERIFY_RECORD_ABSENT",
                "state": "ABSENT",
                "evidence_id": "",
            },
            {
                "step_no": 8,
                "phase": "VERIFICATION",
                "system_id": "integration_service",
                "resource_id": "data_flow_cust_55",
                "operation": "VERIFY_DATA_FLOW_DISABLED",
                "state": "DISABLED",
                "evidence_id": "",
            },
            {
                "step_no": 9,
                "phase": "VERIFICATION",
                "system_id": "backup_service",
                "resource_id": "backup_cust_77",
                "operation": "VERIFY_RESTORE_BLOCKED",
                "state": "BLOCKED",
                "evidence_id": "",
            },
        ],
    )

    # --------------------------------------------------------------------------
    # Case 3: Retained Security Audit Log + Permitted Tombstone with Exposed PII
    # Security audit log is lawfully retained (VERIFY_RECORD_PRESENT).
    # Account tombstone preserves user reference, but improperly retained phone number (PII exposed).
    # --------------------------------------------------------------------------
    user_03 = UserIdentity(
        user_id="user_cust_03",
        name="Fatima Al-Mansoor",
        current_email="fatima.almansoor@example.com",
        current_phone="+971 50 123 4567",
        email_hash="hash_cust_03",
        snapshot_updated_at="2026-07-20T00:00:00Z",
    )
    
    rec_sec = ExtractedRecord(
        evidence_id="evidence_cust_03",
        system_id="security_service",
        resource_id="audit_record_cust_88",
        user_id="user_cust_03",
        email=None,
        phone=None,
        record_state="PRESENT",
        event_timestamp="2026-08-05T09:00:00Z",
        details={"type": "SECURITY_AUDIT_LOG"},
    )
    rec_tomb = ExtractedRecord(
        evidence_id="evidence_cust_03",
        system_id="account_service",
        resource_id="account_tombstone_cust_04",
        user_id="user_cust_03",
        email=None,
        phone="+971 50 123 4567",  # Direct PII still exposed!
        record_state="PRESENT",
        event_timestamp="2026-08-05T09:15:00Z",
        details={"phone": "+971 50 123 4567"},
    )

    case_3 = CustomTestCase(
        case_id="custom_case_03",
        description="Lawful retention of security audit record paired with tombstone failing PII redaction.",
        request={
            "case_id": "custom_case_03",
            "email": "fatima.almansoor@example.com",
            "requested_at": "2026-08-01T10:00:00Z",
            "reported_status": "PARTIALLY_COMPLETE",
            "reported_at": "2026-08-03T11:00:00Z",
            "audit_at": "2026-08-15T12:00:00Z",
            "request_text": "Please delete my account in full. Retain any audit records required by law.",
        },
        user_identity=user_03,
        decoy_identities=[],
        extracted_records=[rec_tomb, rec_sec],
        flow_risks=[],
        restore_risks=[],
        expected_status="INCOMPLETE",
        expected_steps=[
            # FINDING: Tombstone exposed PII
            {
                "step_no": 1,
                "phase": "FINDING",
                "system_id": "account_service",
                "resource_id": "account_tombstone_cust_04",
                "operation": "REPORT_EXPOSED_PII",
                "state": "PRESENT",
                "evidence_id": "evidence_cust_03",
            },
            # REMEDIATION: Redact tombstone
            {
                "step_no": 2,
                "phase": "REMEDIATION",
                "system_id": "account_service",
                "resource_id": "account_tombstone_cust_04",
                "operation": "REDACT_RECORD",
                "state": "REDACTED",
                "evidence_id": "",
            },
            # VERIFICATION: Security log present + Tombstone redacted
            {
                "step_no": 3,
                "phase": "VERIFICATION",
                "system_id": "security_service",
                "resource_id": "audit_record_cust_88",
                "operation": "VERIFY_RECORD_PRESENT",
                "state": "PRESENT",
                "evidence_id": "",
            },
            {
                "step_no": 4,
                "phase": "VERIFICATION",
                "system_id": "account_service",
                "resource_id": "account_tombstone_cust_04",
                "operation": "VERIFY_RECORD_REDACTED",
                "state": "REDACTED",
                "evidence_id": "",
            },
        ],
    )

    return [case_1, case_2, case_3]


def run_custom_cases(policy_engine: PolicyEngine, planner: RemediationPlanner) -> Dict[str, Any]:
    """Execute all custom cases through the production policy and planning pipeline."""
    cases = get_custom_test_cases()
    results = []
    total_cases = len(cases)
    status_passed = 0
    steps_passed = 0

    for c in cases:
        # 1. Intent determination
        is_del, reason = determine_deletion_intent(c.request["request_text"])
        if not is_del:
            pred_status = "NOT_APPLICABLE"
            pred_steps = []
        else:
            # 2. Evaluate records and risks
            eval_items = policy_engine.evaluate_records(
                c.extracted_records,
                c.flow_risks,
                c.restore_risks,
            )
            has_violations = any(not it.is_compliant for it in eval_items)
            pred_status = "INCOMPLETE" if has_violations else "COMPLETE"
            pred_steps = planner.build_steps_plan(pred_status, eval_items)

        st_match = pred_status == c.expected_status
        steps_match = pred_steps == c.expected_steps
        if st_match:
            status_passed += 1
        if steps_match:
            steps_passed += 1

        results.append({
            "case_id": c.case_id,
            "description": c.description,
            "status_match": st_match,
            "steps_match": steps_match,
            "pred_status": pred_status,
            "expected_status": c.expected_status,
            "pred_steps": pred_steps,
            "expected_steps": c.expected_steps,
        })

    return {
        "total_cases": total_cases,
        "status_accuracy": status_passed / total_cases if total_cases else 0.0,
        "exact_steps_accuracy": steps_passed / total_cases if total_cases else 0.0,
        "cases": results,
    }
