"""policy_engine.py - Evaluates deletion rules against subject evidence and activity.

Directly applies deletion_rules.csv rules across all data categories and determines:
1. Status: COMPLETE, INCOMPLETE, or NOT_APPLICABLE.
2. Findings: Prohibited remaining records, exposed PII, active sync flows, and restore risks.
3. Preserved records: Lawful retentions (security audit logs, legal hold, tombstones).
4. Treatment actions required: DELETE, REDACT, ANONYMIZE, RETAIN.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Any
import pandas as pd

from code.config import DELETION_RULES_PATH
from code.audit.evidence_engine import ExtractedRecord, normalize_system
from code.audit.activity_tracker import FlowAndRiskFact


@dataclass
class DeletionRule:
    rule_id: str
    data_category: str
    condition: str
    required_action: str  # DELETE, REDACT, ANONYMIZE, RETAIN


@dataclass
class EvaluatedItem:
    system_id: str
    resource_id: str
    data_category: str
    rule_id: str
    required_action: str
    current_state: str  # PRESENT, REDACTED, ANONYMIZED, ABSENT, ACTIVE, DISABLED, BLOCKED
    is_compliant: bool
    evidence_id: str
    finding_op: Optional[str] = None
    finding_state: Optional[str] = None
    remediation_op: Optional[str] = None
    remediation_state: Optional[str] = None
    verification_op: Optional[str] = None
    verification_state: Optional[str] = None


class PolicyEngine:
    """Parses deletion_rules.csv and evaluates records and risks against policy."""

    def __init__(self, rules_path: Path = DELETION_RULES_PATH):
        self.rules_path = rules_path
        self.rules: Dict[str, DeletionRule] = {}
        self._load_rules()

    def _load_rules(self) -> None:
        if not self.rules_path.exists():
            return
        df = pd.read_csv(self.rules_path)
        for _, row in df.iterrows():
            rid = str(row["rule_id"]).strip()
            cat = str(row["data_category"]).strip()
            cond = str(row["condition"]).strip()
            act = str(row["required_action"]).strip()
            self.rules[cat] = DeletionRule(
                rule_id=rid,
                data_category=cat,
                condition=cond,
                required_action=act,
            )

    def classify_resource_category(self, system_id: str, resource_id: str, details: Dict[str, Any]) -> str:
        """Categorize resource into official data categories based on system and resource prefix."""
        res_lower = resource_id.lower()
        sys_lower = system_id.lower()
        if details.get("category"):
            return str(details["category"]).strip()
        if details.get("email_opt_in") is True or str(details.get("email_opt_in", "")).lower() == "true":
            return "MARKETING_PROFILE"
        if "tombstone" in res_lower:
            return "ACCOUNT_TOMBSTONE"
        if "audit_record" in res_lower or "security" in sys_lower:
            return "SECURITY_AUDIT_LOG"
        if "search" in res_lower or "search" in sys_lower:
            return "SEARCH_INDEX_ENTRY"
        if "analytics" in res_lower or "telemetry" in res_lower or "analytics" in sys_lower:
            return "ANALYTICS_PROFILE"
        if "support" in res_lower or "ticket" in res_lower or "support" in sys_lower:
            # Check if attachment, contact index, or message
            if (
                "attachment" in res_lower
                or "doc" in res_lower
                or details.get("file_name")
                or details.get("is_attachment")
                or details.get("source") == "legacy_contact_index"
                or details.get("event") == "deletion_marker_check"
            ):
                return "SUPPORT_ATTACHMENT"
            return "SUPPORT_MESSAGE"
        if "export" in res_lower or "export" in sys_lower:
            return "USER_EXPORT"
        if "marketing" in res_lower or "marketing" in sys_lower:
            return "MARKETING_PROFILE"
        if "backup" in res_lower or "backup" in sys_lower:
            return "BACKUP_ARCHIVE"
        if "connector" in res_lower or "data_flow" in res_lower or "integration" in sys_lower:
            return "SECONDARY_IDENTIFIER"

        return "USER_PROFILE"

    def evaluate_record(
        self,
        system_id: str,
        resource_id: str,
        data_category: Optional[str] = None,
        current_state: str = "PRESENT",
        details: Optional[Dict[str, Any]] = None,
        evidence_id: str = "",
    ) -> EvaluatedItem:
        """Evaluate a single record against deletion policy."""
        details = details or {}
        norm_sys = normalize_system(system_id, resource_id)
        cat = data_category or self.classify_resource_category(norm_sys, resource_id, details)
        rule = self.rules.get(cat, DeletionRule("rule_01", cat, "Always", "DELETE"))

        state = current_state
        is_compliant = False
        finding_op = None
        finding_state = None
        remed_op = None
        remed_state = None
        verif_op = None
        verif_state = None

        if "data_flow" in resource_id.lower() or "connector" in resource_id.lower():
            if state == "DISABLED":
                is_compliant = True
                verif_op = "VERIFY_DATA_FLOW_DISABLED"
                verif_state = "DISABLED"
            else:
                is_compliant = False
                finding_op = "REPORT_ACTIVE_DATA_FLOW"
                finding_state = "ACTIVE"
                remed_op = "DISABLE_DATA_FLOW"
                remed_state = "DISABLED"
                verif_op = "VERIFY_DATA_FLOW_DISABLED"
                verif_state = "DISABLED"

        elif "backup" in resource_id.lower():
            if state == "BLOCKED":
                is_compliant = True
                verif_op = "VERIFY_RESTORE_BLOCKED"
                verif_state = "BLOCKED"
            else:
                is_compliant = False
                finding_op = "REPORT_RESTORE_RISK"
                finding_state = "ACTIVE"
                remed_op = "BLOCK_RESTORE"
                remed_state = "BLOCKED"
                verif_op = "VERIFY_RESTORE_BLOCKED"
                verif_state = "BLOCKED"

        elif rule.required_action == "DELETE":
            if state == "ABSENT":
                is_compliant = True
                verif_op = "VERIFY_RECORD_ABSENT"
                verif_state = "ABSENT"
            else:
                is_compliant = False
                finding_op = "REPORT_REMAINING_RECORD"
                finding_state = "PRESENT"
                remed_op = "DELETE_RECORD"
                remed_state = "ABSENT"
                verif_op = "VERIFY_RECORD_ABSENT"
                verif_state = "ABSENT"

        elif rule.required_action == "REDACT":
            if state == "REDACTED":
                is_compliant = True
                verif_op = "VERIFY_RECORD_REDACTED"
                verif_state = "REDACTED"
            else:
                is_compliant = False
                finding_op = "REPORT_EXPOSED_PII"
                finding_state = "PRESENT"
                remed_op = "REDACT_RECORD"
                remed_state = "REDACTED"
                verif_op = "VERIFY_RECORD_REDACTED"
                verif_state = "REDACTED"

        elif rule.required_action == "ANONYMIZE":
            if state == "ANONYMIZED":
                is_compliant = True
                verif_op = "VERIFY_RECORD_ANONYMIZED"
                verif_state = "ANONYMIZED"
            else:
                is_compliant = False
                finding_op = "REPORT_EXPOSED_PII"
                finding_state = "PRESENT"
                remed_op = "ANONYMIZE_RECORD"
                remed_state = "ANONYMIZED"
                verif_op = "VERIFY_RECORD_ANONYMIZED"
                verif_state = "ANONYMIZED"

        elif rule.required_action == "RETAIN":
            is_compliant = True
            verif_op = "VERIFY_RECORD_PRESENT"
            verif_state = "PRESENT"

        return EvaluatedItem(
            system_id=norm_sys,
            resource_id=resource_id,
            data_category=cat,
            rule_id=rule.rule_id,
            required_action=rule.required_action,
            current_state=state,
            is_compliant=is_compliant,
            evidence_id=evidence_id,
            finding_op=finding_op,
            finding_state=finding_state,
            remediation_op=remed_op,
            remediation_state=remed_state,
            verification_op=verif_op,
            verification_state=verif_state,
        )

    def evaluate_records(
        self,
        extracted_records: List[ExtractedRecord],
        flow_risks: List[FlowAndRiskFact],
        restore_risks: List[FlowAndRiskFact],
    ) -> List[EvaluatedItem]:
        """Evaluate each extracted record and risk against applicable deletion policy."""
        evaluated: List[EvaluatedItem] = []

        # 1. Evaluate extracted records
        for rec in extracted_records:
            item = self.evaluate_record(
                system_id=rec.system_id,
                resource_id=rec.resource_id,
                current_state=rec.record_state,
                details=rec.details,
                evidence_id=rec.evidence_id,
            )
            evaluated.append(item)

        # 2. Evaluate active data flows
        for flow in flow_risks:
            evaluated.append(
                EvaluatedItem(
                    system_id=flow.system_id,
                    resource_id=flow.resource_id,
                    data_category="SECONDARY_IDENTIFIER",
                    rule_id="rule_02",
                    required_action="DELETE",
                    current_state="ACTIVE",
                    is_compliant=False,
                    evidence_id=flow.evidence_id or "",
                    finding_op="REPORT_ACTIVE_DATA_FLOW",
                    finding_state="ACTIVE",
                    remediation_op="DISABLE_DATA_FLOW",
                    remediation_state="DISABLED",
                    verification_op="VERIFY_DATA_FLOW_DISABLED",
                    verification_state="DISABLED",
                )
            )

        # 3. Evaluate restore risks
        for rrisk in restore_risks:
            evaluated.append(
                EvaluatedItem(
                    system_id=rrisk.system_id,
                    resource_id=rrisk.resource_id,
                    data_category="BACKUP_ARCHIVE",
                    rule_id="rule_14",
                    required_action="RETAIN",
                    current_state="ACTIVE",
                    is_compliant=False,
                    evidence_id=rrisk.evidence_id or "",
                    finding_op="REPORT_RESTORE_RISK",
                    finding_state="ACTIVE",
                    remediation_op="BLOCK_RESTORE",
                    remediation_state="BLOCKED",
                    verification_op="VERIFY_RESTORE_BLOCKED",
                    verification_state="BLOCKED",
                )
            )

        return evaluated
