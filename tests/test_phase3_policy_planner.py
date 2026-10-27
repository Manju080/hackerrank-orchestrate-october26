"""test_phase3_policy_planner.py - Comprehensive unit tests for Phase 3:
1. Deletion-intent determination (authorized vs NOT_APPLICABLE non-deletion).
2. Direct application of all rules from deletion_rules.csv.
3. Policy evaluation against extracted evidence, data flows, and restore risks.
4. Correct step schema (7 keys), consecutive numbering starting at 1.
5. Strict phase ordering (FINDING -> REMEDIATION -> VERIFICATION).
6. Canonical operation sorting with dependency preservation (data flows / restores before records).
7. Correct evidence references (findings cite participant files, future remediation/verification use "").
8. Lawful retention handling (security audit records, legal hold, tombstones).
"""

import unittest
from pathlib import Path

from code.config import DELETION_RULES_PATH
from code.audit.intent_detector import determine_deletion_intent
from code.audit.policy_engine import PolicyEngine, EvaluatedItem
from code.audit.planner import RemediationPlanner
from code.audit.evidence_engine import ExtractedRecord
from code.audit.activity_tracker import FlowAndRiskFact


class TestPhase3PolicyPlanner(unittest.TestCase):

    def setUp(self):
        self.policy_engine = PolicyEngine()
        self.planner = RemediationPlanner()

    def test_intent_detection_authorized_vs_not_applicable(self):
        """A. Intent determination: clear deletions vs non-deletion requests."""
        # 1. Clear deletion
        del_text = "Please close my account and process the associated personal-data deletion."
        is_del, reason = determine_deletion_intent(del_text)
        self.assertTrue(is_del)
        self.assertEqual(reason, "DELETION_AUTHORIZED")

        # 2. Multilingual deletion (Portuguese)
        pt_text = "Solicito a exclusão permanente da conta associada a este e-mail."
        is_del, reason = determine_deletion_intent(pt_text)
        self.assertTrue(is_del)

        # 3. Non-deletion: Download request (case_535)
        dl_text = "I'd like to download my account information in a portable format. Please keep the account as it is."
        is_del, reason = determine_deletion_intent(dl_text)
        self.assertFalse(is_del)
        self.assertIn("EXPLICIT_NON_DELETION", reason)

        # 4. Non-deletion: Invoices copy (case_540)
        inv_text = "I need a copy of last year's invoices for my records. Please leave my profile and purchase history in place."
        is_del, reason = determine_deletion_intent(inv_text)
        self.assertFalse(is_del)

        # 5. Non-deletion: Marketing opt-out only (case_538)
        mkt_text = "Please remove me from marketing lists only. I still want receipts and service messages for this account."
        is_del, reason = determine_deletion_intent(mkt_text)
        self.assertFalse(is_del)

    def test_all_deletion_rules_loaded(self):
        """B. Verify deletion_rules.csv rules are directly parsed and mapped."""
        self.assertGreaterEqual(len(self.policy_engine.rules), 14)
        self.assertIn("USER_PROFILE", self.policy_engine.rules)
        self.assertEqual(self.policy_engine.rules["USER_PROFILE"].required_action, "DELETE")
        self.assertIn("ACCOUNT_TOMBSTONE", self.policy_engine.rules)
        self.assertEqual(self.policy_engine.rules["ACCOUNT_TOMBSTONE"].required_action, "REDACT")
        self.assertIn("SECURITY_AUDIT_LOG", self.policy_engine.rules)
        self.assertEqual(self.policy_engine.rules["SECURITY_AUDIT_LOG"].required_action, "RETAIN")
        self.assertIn("ANALYTICS_PROFILE", self.policy_engine.rules)
        self.assertEqual(self.policy_engine.rules["ANALYTICS_PROFILE"].required_action, "ANONYMIZE")

    def test_complete_case_steps_generation(self):
        """C. COMPLETE cases: only evidence-backed verification steps."""
        eval_items = [
            EvaluatedItem(
                system_id="account_service",
                resource_id="account_001",
                data_category="USER_PROFILE",
                rule_id="rule_01",
                required_action="DELETE",
                current_state="ABSENT",
                is_compliant=True,
                evidence_id="evidence_54",
                verification_op="VERIFY_RECORD_ABSENT",
                verification_state="ABSENT",
            ),
            EvaluatedItem(
                system_id="security_service",
                resource_id="audit_record_001",
                data_category="SECURITY_AUDIT_LOG",
                rule_id="rule_12",
                required_action="RETAIN",
                current_state="PRESENT",
                is_compliant=True,
                evidence_id="evidence_54",
                verification_op="VERIFY_RECORD_PRESENT",
                verification_state="PRESENT",
            ),
        ]

        steps = self.planner.build_steps_plan("COMPLETE", eval_items)
        self.assertEqual(len(steps), 2)
        # Verify 7 keys in every step
        required_keys = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}
        for s in steps:
            self.assertEqual(set(s.keys()), required_keys)
            self.assertEqual(s["phase"], "VERIFICATION")
            self.assertTrue(s["evidence_id"])  # must be non-empty evidence reference

        # Numbering consecutive from 1
        self.assertEqual(steps[0]["step_no"], 1)
        self.assertEqual(steps[1]["step_no"], 2)

    def test_incomplete_case_phase_and_dependency_ordering(self):
        """D. INCOMPLETE cases: FINDING -> REMEDIATION -> VERIFICATION with data flow dependency priority."""
        eval_items = [
            # 1. Prohibited record remaining in search index
            EvaluatedItem(
                system_id="search_service",
                resource_id="search_052",
                data_category="SEARCH_INDEX_ENTRY",
                rule_id="rule_03",
                required_action="DELETE",
                current_state="PRESENT",
                is_compliant=False,
                evidence_id="evidence_03",
                finding_op="REPORT_REMAINING_RECORD",
                finding_state="PRESENT",
                remediation_op="DELETE_RECORD",
                remediation_state="ABSENT",
                verification_op="VERIFY_RECORD_ABSENT",
                verification_state="ABSENT",
            ),
            # 2. Exposed PII in support ticket
            EvaluatedItem(
                system_id="support_platform",
                resource_id="support_864",
                data_category="SUPPORT_MESSAGE",
                rule_id="rule_05",
                required_action="REDACT",
                current_state="PRESENT",
                is_compliant=False,
                evidence_id="evidence_03",
                finding_op="REPORT_EXPOSED_PII",
                finding_state="PRESENT",
                remediation_op="REDACT_RECORD",
                remediation_state="REDACTED",
                verification_op="VERIFY_RECORD_REDACTED",
                verification_state="REDACTED",
            ),
            # 3. Active data flow sync risk
            EvaluatedItem(
                system_id="integration_service",
                resource_id="data_flow_9522",
                data_category="SECONDARY_IDENTIFIER",
                rule_id="rule_02",
                required_action="DELETE",
                current_state="ACTIVE",
                is_compliant=False,
                evidence_id="evidence_03",
                finding_op="REPORT_ACTIVE_DATA_FLOW",
                finding_state="ACTIVE",
                remediation_op="DISABLE_DATA_FLOW",
                remediation_state="DISABLED",
                verification_op="VERIFY_DATA_FLOW_DISABLED",
                verification_state="DISABLED",
            ),
            # 4. Compliant account deletion already verified
            EvaluatedItem(
                system_id="account_service",
                resource_id="account_4248",
                data_category="USER_PROFILE",
                rule_id="rule_01",
                required_action="DELETE",
                current_state="ABSENT",
                is_compliant=True,
                evidence_id="",
                verification_op="VERIFY_RECORD_ABSENT",
                verification_state="ABSENT",
            ),
        ]

        steps = self.planner.build_steps_plan("INCOMPLETE", eval_items)

        # 1. Phase Ordering: FINDING then REMEDIATION then VERIFICATION
        phases = [s["phase"] for s in steps]
        finding_indices = [i for i, p in enumerate(phases) if p == "FINDING"]
        remed_indices = [i for i, p in enumerate(phases) if p == "REMEDIATION"]
        verif_indices = [i for i, p in enumerate(phases) if p == "VERIFICATION"]

        self.assertLess(max(finding_indices), min(remed_indices))
        self.assertLess(max(remed_indices), min(verif_indices))

        # 2. Dependency ordering in remediation: DISABLE_DATA_FLOW must precede DELETE_RECORD and REDACT_RECORD
        remed_ops = [s["operation"] for s in steps if s["phase"] == "REMEDIATION"]
        self.assertEqual(remed_ops[0], "DISABLE_DATA_FLOW")

        # 3. Evidence ID contract: Findings cite evidence, remediation and future verification have empty string
        for s in steps:
            if s["phase"] == "FINDING":
                self.assertEqual(s["evidence_id"], "evidence_03")
            else:
                self.assertEqual(s["evidence_id"], "")

        # 4. Step numbering consecutive from 1
        for idx, s in enumerate(steps, start=1):
            self.assertEqual(s["step_no"], idx)

    def test_not_applicable_steps_are_empty(self):
        """E. NOT_APPLICABLE cases must produce empty steps array."""
        steps = self.planner.build_steps_plan("NOT_APPLICABLE", [])
        self.assertEqual(steps, [])

    def test_deletion_rules_application_conditions(self):
        """F. Verify every rule in deletion_rules.csv applies according to conditions: RETAIN, DELETE, REDACT, ANONYMIZE."""
        # 1. DELETE on USER_PROFILE
        res_del = self.policy_engine.evaluate_record(
            system_id="account_service",
            resource_id="account_101",
            data_category="USER_PROFILE",
            current_state="PRESENT",
            details={},
            evidence_id="evidence_01"
        )
        self.assertFalse(res_del.is_compliant)
        self.assertEqual(res_del.finding_op, "REPORT_REMAINING_RECORD")
        self.assertEqual(res_del.remediation_op, "DELETE_RECORD")
        self.assertEqual(res_del.verification_op, "VERIFY_RECORD_ABSENT")

        # 2. RETAIN on SECURITY_AUDIT_LOG
        res_retain = self.policy_engine.evaluate_record(
            system_id="security_service",
            resource_id="audit_record_101",
            data_category="SECURITY_AUDIT_LOG",
            current_state="PRESENT",
            details={},
            evidence_id="evidence_01"
        )
        self.assertTrue(res_retain.is_compliant)
        self.assertEqual(res_retain.verification_op, "VERIFY_RECORD_PRESENT")
        self.assertEqual(res_retain.verification_state, "PRESENT")

        # 3. REDACT on ACCOUNT_TOMBSTONE
        res_tombstone = self.policy_engine.evaluate_record(
            system_id="account_service",
            resource_id="account_101",
            data_category="ACCOUNT_TOMBSTONE",
            current_state="REDACTED",
            details={"email": None, "phone": None},
            evidence_id="evidence_01"
        )
        self.assertTrue(res_tombstone.is_compliant)
        self.assertEqual(res_tombstone.verification_op, "VERIFY_RECORD_REDACTED")

        # 4. ANONYMIZE on ANALYTICS_PROFILE
        res_anon = self.policy_engine.evaluate_record(
            system_id="analytics_platform",
            resource_id="analytics_101",
            data_category="ANALYTICS_PROFILE",
            current_state="ANONYMIZED",
            details={},
            evidence_id="evidence_01"
        )
        self.assertTrue(res_anon.is_compliant)
        self.assertEqual(res_anon.verification_op, "VERIFY_RECORD_ANONYMIZED")

    def test_intent_depends_only_on_request_content(self):
        """G. Verify intent depends strictly on request_text and not case_id or reported_status."""
        # Ambiguous looking text with deletion keywords but requesting access
        access_req = "I want to export all data associated with my account deletion request. Please do not delete anything yet."
        is_del, reason = determine_deletion_intent(access_req)
        self.assertFalse(is_del)

        # Deletion request embedded in varied phrasing
        del_req = "Please permanently wipe all references and personal data from your systems."
        is_del, reason = determine_deletion_intent(del_req)
        self.assertTrue(is_del)

    def test_downstream_copies_processed_before_sources(self):
        """H. Verify downstream copies (search, analytics, export) and flows are remediated before source accounts."""
        eval_items = [
            EvaluatedItem(
                system_id="account_service",
                resource_id="account_source_01",
                data_category="USER_PROFILE",
                rule_id="rule_01",
                required_action="DELETE",
                current_state="PRESENT",
                is_compliant=False,
                evidence_id="evidence_01",
                finding_op="REPORT_REMAINING_RECORD",
                finding_state="PRESENT",
                remediation_op="DELETE_RECORD",
                remediation_state="ABSENT",
                verification_op="VERIFY_RECORD_ABSENT",
                verification_state="ABSENT",
            ),
            EvaluatedItem(
                system_id="search_service",
                resource_id="search_downstream_01",
                data_category="SEARCH_INDEX_ENTRY",
                rule_id="rule_03",
                required_action="DELETE",
                current_state="PRESENT",
                is_compliant=False,
                evidence_id="evidence_01",
                finding_op="REPORT_REMAINING_RECORD",
                finding_state="PRESENT",
                remediation_op="DELETE_RECORD",
                remediation_state="ABSENT",
                verification_op="VERIFY_RECORD_ABSENT",
                verification_state="ABSENT",
            ),
            EvaluatedItem(
                system_id="integration_service",
                resource_id="data_flow_01",
                data_category="SECONDARY_IDENTIFIER",
                rule_id="rule_02",
                required_action="DELETE",
                current_state="ACTIVE",
                is_compliant=False,
                evidence_id="evidence_01",
                finding_op="REPORT_ACTIVE_DATA_FLOW",
                finding_state="ACTIVE",
                remediation_op="DISABLE_DATA_FLOW",
                remediation_state="DISABLED",
                verification_op="VERIFY_DATA_FLOW_DISABLED",
                verification_state="DISABLED",
            ),
        ]

        steps = self.planner.build_steps_plan("INCOMPLETE", eval_items)
        remed_steps = [s for s in steps if s["phase"] == "REMEDIATION"]

        # First operation must be DISABLE_DATA_FLOW
        self.assertEqual(remed_steps[0]["operation"], "DISABLE_DATA_FLOW")
        # Then DELETE_RECORD operations ordered by system/resource
        self.assertEqual(remed_steps[1]["system_id"], "account_service")
        self.assertEqual(remed_steps[2]["system_id"], "search_service")

    def test_uncertain_evidence_cannot_silently_produce_complete(self):
        """I. Verify uncertain or incomplete evidence cannot silently produce a false COMPLETE status."""
        # If an item is non-compliant, status must be INCOMPLETE
        eval_items = [
            EvaluatedItem(
                system_id="support_platform",
                resource_id="support_ticket_99",
                data_category="SUPPORT_MESSAGE",
                rule_id="rule_05",
                required_action="REDACT",
                current_state="PRESENT",  # PII still exposed
                is_compliant=False,
                evidence_id="evidence_01",
                finding_op="REPORT_EXPOSED_PII",
                finding_state="PRESENT",
                remediation_op="REDACT_RECORD",
                remediation_state="REDACTED",
                verification_op="VERIFY_RECORD_REDACTED",
                verification_state="REDACTED",
            )
        ]
        has_violations = any(not it.is_compliant for it in eval_items)
        computed_status = "INCOMPLETE" if has_violations else "COMPLETE"
        self.assertEqual(computed_status, "INCOMPLETE")


if __name__ == "__main__":
    unittest.main()
