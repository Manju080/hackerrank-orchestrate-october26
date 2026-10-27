"""Unit tests for Phase 2: Activity Tracker, Flow Detection, and Restore Risks."""

import unittest
import tempfile
from pathlib import Path
import pandas as pd

from code.audit.activity_tracker import ActivityTracker, ActivityEvent


class TestPhase2Activity(unittest.TestCase):
    """Test activity tracking, temporal filtering, and risk detection."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.activity_path = Path(self.temp_dir.name) / "test_system_activity.csv"

        df = pd.DataFrame([
            {
                "activity_id": "act_01",
                "event_time": "2026-07-01T10:00:00Z",
                "event_type": "INDEX_RECORD",
                "source_system": "account_service",
                "target_system": "search_service",
                "resource_id": "search_101",
                "reported_result": "SUCCESS",
                "details": "Indexed search_101",
            },
            {
                "activity_id": "act_02",
                "event_time": "2026-08-15T12:00:00Z",
                "event_type": "SYNC_RECORD",
                "source_system": "integration_service",
                "target_system": "analytics_platform",
                "resource_id": "data_flow_202",
                "reported_result": "SUCCESS",
                "details": "Active sync job for data_flow_202",
            },
            {
                "activity_id": "act_03",
                "event_time": "2026-09-01T15:00:00Z",
                "event_type": "BACKUP_RECORD",
                "source_system": "backup_service",
                "target_system": "archive_service",
                "resource_id": "backup_303",
                "reported_result": "SUCCESS",
                "details": "Backup snapshot containing account_001",
            },
            # Event occurring after cutoff
            {
                "activity_id": "act_04",
                "event_time": "2026-10-05T00:00:00Z",
                "event_type": "RESTORE_RECORD",
                "source_system": "backup_service",
                "target_system": "account_service",
                "resource_id": "backup_303",
                "reported_result": "SUCCESS",
                "details": "Future restore job",
            },
        ])
        df.to_csv(self.activity_path, index=False)
        self.tracker = ActivityTracker(activity_path=self.activity_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_chronological_sorting(self):
        """Events are sorted chronologically."""
        times = [ev.event_time for ev in self.tracker.events]
        self.assertEqual(times, sorted(times))

    def test_rejection_of_events_after_cutoff(self):
        """Events strictly after audit_at are rejected from queries."""
        cutoff = "2026-09-15T00:00:00Z"
        flows = self.tracker.detect_data_flow_risks({"data_flow_202"}, audit_at=cutoff)
        self.assertEqual(len(flows), 1)

        # Future restore event act_04 must NOT appear in restore risks
        risks = self.tracker.detect_restore_risks({"account_001"}, audit_at=cutoff)
        self.assertEqual(len(risks), 1)
        self.assertEqual(risks[0].evidence_id, "act_03")

    def test_detect_data_flow_risks(self):
        """Active sync jobs are detected as data flow risks."""
        flows = self.tracker.detect_data_flow_risks(
            {"data_flow_202"}, audit_at="2026-09-30T00:00:00Z"
        )
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].fact_type, "DATA_FLOW")
        self.assertEqual(flows[0].system_id, "analytics_platform")
        self.assertTrue(flows[0].is_active_risk)

    def test_detect_restore_risks(self):
        """Backups containing user data are detected as restore risks."""
        risks = self.tracker.detect_restore_risks(
            {"account_001"}, audit_at="2026-09-30T00:00:00Z"
        )
        self.assertEqual(len(risks), 1)
        self.assertEqual(risks[0].fact_type, "RESTORE_RISK")
        self.assertEqual(risks[0].resource_id, "backup_303")


if __name__ == "__main__":
    unittest.main()
