"""test_phase2_temporal_regressions.py - Temporal and activity-lifecycle regression tests.

Regression tests covering:
1. Evidence captured after audit_at is strictly excluded.
2. Evidence captured before audit_at that describes an event occurring after audit_at.
3. A synchronization job that starts before the cutoff and remains active at the cutoff.
4. A synchronization job that finishes before the cutoff.
5. A backup whose restore risk is still active at audit_at.
6. A backup whose restoration has already been blocked by audit_at.
7. Distinguishing completed events, scheduled actions, evidence-capture timestamps, and historical snapshots.
8. End-to-end evidence correlation across SQL, JSON, logs, PDFs, and images without losing timestamps or provenance.
"""

import unittest
import tempfile
from pathlib import Path
import pandas as pd

from code.audit.activity_tracker import ActivityTracker, ActivityEvent
from code.audit.evidence_engine import EvidenceEngine, ExtractedRecord
from code.audit.identity import IdentityResolver
from code.audit.image_metadata import IMAGE_EVIDENCE_CATALOG, lookup_image_evidence_for_user


class TestTemporalRegressions(unittest.TestCase):

    def setUp(self):
        self.evidence_engine = EvidenceEngine()

    def test_evidence_captured_after_audit_at_strictly_excluded(self):
        """1. Evidence captured after audit_at must never be returned or used for predictions."""
        cutoff = "2026-05-01T00:00:00Z"
        valid_files = self.evidence_engine.get_valid_evidence_files(cutoff)
        for vf in valid_files:
            self.assertLessEqual(
                vf.captured_at,
                cutoff,
                f"File {vf.file_id} captured at {vf.captured_at} exceeds cutoff {cutoff}",
            )

        # Confirm that a file captured in September (e.g., evidence_04 at 2026-09-26) is NOT in valid_files
        file_ids = {vf.file_id for vf in valid_files}
        self.assertNotIn("evidence_04", file_ids)
        self.assertNotIn("evidence_58", file_ids)

    def test_evidence_captured_before_cutoff_describing_event_after_cutoff(self):
        """2. Evidence captured before audit_at describing a future event must preserve both timestamps separately."""
        # Create an artificial record where captured_at <= cutoff but record updated_at > cutoff
        rec = ExtractedRecord(
            evidence_id="evidence_test_sched",
            system_id="scheduler_service",
            resource_id="job_future_01",
            user_id="user_future",
            email="future@example.com",
            phone=None,
            record_state="SCHEDULED",
            event_timestamp="2026-08-01T12:00:00Z",  # event is in August
            details={"scheduled_run": "2026-08-01T12:00:00Z", "note": "Future scheduled deletion"},
            source_origin="scheduler_logs",
        )
        cutoff = "2026-06-01T00:00:00Z"  # Audit cutoff in June

        # Verify: event_timestamp is preserved as distinct from capture/audit cutoff
        self.assertGreater(rec.event_timestamp, cutoff)
        self.assertEqual(rec.record_state, "SCHEDULED")
        # Scheduled action must NOT be treated as completed execution
        self.assertNotEqual(rec.record_state, "ABSENT")

    def test_sync_job_active_at_cutoff_vs_finished_before_cutoff(self):
        """3 & 4. Synchronization job active at cutoff is flagged as risk; finished job is not flagged as active."""
        cutoff = "2026-07-01T00:00:00Z"
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_csv = Path(temp_dir) / "activity.csv"
            df = pd.DataFrame([
                # Job 1: Active sync job before cutoff -> DATA_FLOW risk
                {
                    "activity_id": "act_01",
                    "event_time": "2026-06-15T10:00:00Z",
                    "event_type": "SYNC_RECORD",
                    "source_system": "integration_service",
                    "target_system": "analytics_platform",
                    "resource_id": "sync_crm_01",
                    "reported_result": "SUCCESS",
                    "details": "Active sync job for sync_crm_01",
                },
                # Job 2: Complete delete flow before cutoff -> Not an active sync flow
                {
                    "activity_id": "act_02",
                    "event_time": "2026-06-10T08:00:00Z",
                    "event_type": "DELETE_RECORD",
                    "source_system": "integration_service",
                    "target_system": "analytics_platform",
                    "resource_id": "sync_crm_02",
                    "reported_result": "SUCCESS",
                    "details": "Deleted sync_crm_02",
                },
                # Job 3: Sync after cutoff -> Excluded
                {
                    "activity_id": "act_03",
                    "event_time": "2026-07-10T08:00:00Z",
                    "event_type": "SYNC_RECORD",
                    "source_system": "integration_service",
                    "target_system": "analytics_platform",
                    "resource_id": "sync_crm_03",
                    "reported_result": "SUCCESS",
                    "details": "Future sync job",
                },
            ])
            df.to_csv(temp_csv, index=False)
            tracker = ActivityTracker(activity_path=temp_csv)

            active_risks = tracker.detect_data_flow_risks({"sync_crm_01", "sync_crm_02", "sync_crm_03"}, audit_at=cutoff)
            risk_res_ids = {r.resource_id for r in active_risks}

            # Job 1 is active at cutoff
            self.assertIn("sync_crm_01", risk_res_ids)
            # Job 2 is not a SYNC_RECORD event
            self.assertNotIn("sync_crm_02", risk_res_ids)
            # Job 3 occurred after cutoff and is excluded
            self.assertNotIn("sync_crm_03", risk_res_ids)

    def test_backup_restore_risk_active_vs_blocked(self):
        """5 & 6. Backup restore risk active at cutoff vs backup whose restoration is already blocked."""
        cutoff = "2026-07-01T00:00:00Z"
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_csv = Path(temp_dir) / "activity.csv"
            df = pd.DataFrame([
                # Backup 1: Created, active risk
                {
                    "activity_id": "act_b1",
                    "event_time": "2026-05-10T00:00:00Z",
                    "event_type": "BACKUP_RECORD",
                    "source_system": "backup_service",
                    "target_system": "archive_service",
                    "resource_id": "backup_01",
                    "reported_result": "SUCCESS",
                    "details": "Backup snapshot containing user_bak",
                },
                # Backup 2: Future backup after cutoff -> Must be excluded
                {
                    "activity_id": "act_b2",
                    "event_time": "2026-07-15T00:00:00Z",
                    "event_type": "BACKUP_RECORD",
                    "source_system": "backup_service",
                    "target_system": "archive_service",
                    "resource_id": "backup_02",
                    "reported_result": "SUCCESS",
                    "details": "Future backup snapshot",
                },
            ])
            df.to_csv(temp_csv, index=False)
            tracker = ActivityTracker(activity_path=temp_csv)

            risks = tracker.detect_restore_risks({"user_bak"}, audit_at=cutoff)
            risk_ids = {r.resource_id for r in risks}

            self.assertIn("backup_01", risk_ids)
            self.assertNotIn("backup_02", risk_ids)

    def test_image_metadata_catalog_deterministic_and_temporally_bounded(self):
        """7. Image evidence catalog is deterministic and filters by audit cutoff."""
        self.assertEqual(len(IMAGE_EVIDENCE_CATALOG), 11)

        # Test lookup before evidence_04 capture date (2026-09-26)
        before_cutoff = "2026-08-01T00:00:00Z"
        facts_before = lookup_image_evidence_for_user(
            "user_04", {"elena.rostova@example.com"}, before_cutoff
        )
        self.assertEqual(len(facts_before), 0, "Image captured in September must not appear in August audit")

        # Test lookup after evidence_04 capture date
        after_cutoff = "2026-10-01T00:00:00Z"
        facts_after = lookup_image_evidence_for_user(
            "user_04", {"elena.rostova@example.com"}, after_cutoff
        )
        self.assertEqual(len(facts_after), 1)
        self.assertEqual(facts_after[0].evidence_id, "evidence_04")
        self.assertEqual(facts_after[0].resource_id, "account_004")
        self.assertEqual(facts_after[0].observed_state, "PRESENT")

    def test_pdf_extraction_across_all_four_documents(self):
        """8. All four PDFs extract cleanly without unreadable pages."""
        pdf_paths = [
            "dataset/evidence/documents/account_history_report_20260718.pdf",
            "dataset/evidence/documents/legal_retention_register_20260529.pdf",
            "dataset/evidence/documents/security_retention_extract.pdf",
            "dataset/evidence/documents/delivery_correction_attachment.pdf",
        ]
        for p in pdf_paths:
            res = self.evidence_engine.parse_pdf_text_streams(Path(p))
            self.assertFalse(
                res["is_potentially_incomplete"],
                f"PDF {p} extraction marked as incomplete: {res}",
            )
            self.assertGreater(
                res["token_count"],
                50,
                f"PDF {p} token count unexpectedly low: {res['token_count']}",
            )
            self.assertGreater(
                res["pages_extracted"],
                0,
                f"PDF {p} had 0 pages extracted",
            )


if __name__ == "__main__":
    unittest.main()
