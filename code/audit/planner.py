"""planner.py - Remediation and verification plan builder.

Generates consecutively numbered steps strictly conforming to problem_statement.md:
- Exactly 7 keys: step_no, phase, system_id, resource_id, operation, state, evidence_id
- Consecutive numbering starting at 1
- Ordered phases: FINDING -> REMEDIATION -> VERIFICATION
- Ordered operations:
    FINDING: REPORT_REMAINING_RECORD, REPORT_EXPOSED_PII, REPORT_ACTIVE_DATA_FLOW, REPORT_RESTORE_RISK
    REMEDIATION: DISABLE_DATA_FLOW, BLOCK_RESTORE, DELETE_RECORD, REDACT_RECORD, ANONYMIZE_RECORD
    VERIFICATION: VERIFY_RECORD_ABSENT, VERIFY_RECORD_PRESENT, VERIFY_RECORD_REDACTED, VERIFY_RECORD_ANONYMIZED, VERIFY_DATA_FLOW_DISABLED, VERIFY_RESTORE_BLOCKED
- Evidence reference rules:
    Findings cite participant evidence_id.
    Remediation & post-remediation verification have evidence_id="".
    COMPLETE verification steps cite participant evidence_id.
"""

from typing import Dict, List, Any, Tuple
from code.config import (
    FINDING_OPERATION_ORDER,
    REMEDIATION_OPERATION_ORDER,
    VERIFICATION_OPERATION_ORDER,
)
from code.audit.policy_engine import EvaluatedItem


def verif_sort_key(item: EvaluatedItem) -> Tuple[int, str, str]:
    """Sort verification checks in canonical dependency order."""
    if item.system_id == "account_service" and item.verification_op == "VERIFY_RECORD_ABSENT":
        return (0, item.system_id, item.resource_id)
    if item.verification_op == "VERIFY_RECORD_ABSENT":
        return (1, item.system_id, item.resource_id)
    if item.verification_op == "VERIFY_RECORD_PRESENT":
        return (2, item.system_id, item.resource_id)
    if item.verification_op == "VERIFY_RECORD_REDACTED":
        return (3, item.system_id, item.resource_id)
    if item.verification_op == "VERIFY_RECORD_ANONYMIZED":
        return (4, item.system_id, item.resource_id)
    if item.verification_op == "VERIFY_DATA_FLOW_DISABLED":
        return (5, item.system_id, item.resource_id)
    if item.verification_op == "VERIFY_RESTORE_BLOCKED":
        return (6, item.system_id, item.resource_id)
    return (7, item.system_id, item.resource_id)


class RemediationPlanner:
    """Builds ordered findings, remediation plans, and verification checks."""

    @staticmethod
    def build_steps_plan(deletion_status: str, evaluated_items: List[EvaluatedItem]) -> List[Dict[str, Any]]:
        """Construct consecutively numbered steps according to status and ordering rules."""
        if deletion_status == "NOT_APPLICABLE":
            return []

        steps: List[Dict[str, Any]] = []

        if deletion_status == "COMPLETE":
            # For COMPLETE cases: only evidence-backed verification steps
            verif_items = [it for it in evaluated_items if it.verification_op]
            # Deduplicate by (system_id, resource_id, verification_op)
            seen = set()
            unique_verif = []
            for it in verif_items:
                k = (it.system_id, it.resource_id, it.verification_op)
                if k not in seen:
                    seen.add(k)
                    unique_verif.append(it)

            # Sort by canonical verification dependency order
            unique_verif.sort(key=verif_sort_key)

            step_no = 1
            for it in unique_verif:
                steps.append({
                    "step_no": step_no,
                    "phase": "VERIFICATION",
                    "system_id": it.system_id,
                    "resource_id": it.resource_id,
                    "operation": it.verification_op,
                    "state": it.verification_state,
                    "evidence_id": it.evidence_id or "",
                })
                step_no += 1

            return steps

        elif deletion_status == "INCOMPLETE":
            # 1. FINDINGS (evidence-backed)
            findings = [it for it in evaluated_items if not it.is_compliant and it.finding_op]
            seen_findings = set()
            unique_findings = []
            for f in findings:
                k = (f.system_id, f.resource_id, f.finding_op)
                if k not in seen_findings:
                    seen_findings.add(k)
                    unique_findings.append(f)

            unique_findings.sort(
                key=lambda x: (
                    FINDING_OPERATION_ORDER.get(x.finding_op or "", 99),
                    x.system_id,
                    x.resource_id,
                )
            )

            # 2. REMEDIATION (future work, evidence_id="")
            # Dependency requirement: disable data flows & block restores BEFORE modifying records
            remediations = [it for it in evaluated_items if not it.is_compliant and it.remediation_op]
            seen_remeds = set()
            unique_remeds = []
            for r in remediations:
                k = (r.system_id, r.resource_id, r.remediation_op)
                if k not in seen_remeds:
                    seen_remeds.add(k)
                    unique_remeds.append(r)

            unique_remeds.sort(
                key=lambda x: (
                    REMEDIATION_OPERATION_ORDER.get(x.remediation_op or "", 99),
                    x.system_id,
                    x.resource_id,
                )
            )

            # 3. VERIFICATION (future checks, evidence_id="")
            verifications = [it for it in evaluated_items if it.verification_op]
            seen_verifs = set()
            unique_verifs = []
            for v in verifications:
                k = (v.system_id, v.resource_id, v.verification_op)
                if k not in seen_verifs:
                    seen_verifs.add(k)
                    unique_verifs.append(v)

            unique_verifs.sort(key=verif_sort_key)

            # Assemble consecutively numbered steps
            step_no = 1
            for it in unique_findings:
                steps.append({
                    "step_no": step_no,
                    "phase": "FINDING",
                    "system_id": it.system_id,
                    "resource_id": it.resource_id,
                    "operation": it.finding_op,
                    "state": it.finding_state,
                    "evidence_id": it.evidence_id or "",
                })
                step_no += 1

            for it in unique_remeds:
                steps.append({
                    "step_no": step_no,
                    "phase": "REMEDIATION",
                    "system_id": it.system_id,
                    "resource_id": it.resource_id,
                    "operation": it.remediation_op,
                    "state": it.remediation_state,
                    "evidence_id": "",
                })
                step_no += 1

            for it in unique_verifs:
                steps.append({
                    "step_no": step_no,
                    "phase": "VERIFICATION",
                    "system_id": it.system_id,
                    "resource_id": it.resource_id,
                    "operation": it.verification_op,
                    "state": it.verification_state,
                    "evidence_id": "",
                })
                step_no += 1

            return steps

        return []
