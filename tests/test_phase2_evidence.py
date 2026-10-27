"""Unit tests for Phase 2: Evidence Engine, Parsers, and Manifest Inventory."""

import unittest
import tempfile
from pathlib import Path
import json
import pandas as pd

from code.audit.evidence_engine import EvidenceEngine, EvidenceFileMeta
from code.config import EVIDENCE_FILES_PATH, DATASET_DIR


class TestPhase2Evidence(unittest.TestCase):
    """Test evidence manifest reconciliation, format parsing, and temporal filtering."""

    def setUp(self):
        self.engine = EvidenceEngine()

    def test_manifest_versus_disk_inventory_consistency(self):
        """Reconcile all manifest rows with files on disk."""
        summary = self.engine.get_inventory_summary()
        self.assertTrue(summary["is_consistent"], "Manifest entries must match files on disk")
        self.assertEqual(summary["total_manifest_entries"], 94)
        self.assertEqual(summary["total_files_on_disk"], 94)

        # Check exact category counts
        counts = summary["category_counts"]
        self.assertEqual(counts.get("records", 0), 29)
        self.assertEqual(counts.get("logs", 0), 26)
        self.assertEqual(counts.get("databases", 0), 24)
        self.assertEqual(counts.get("images", 0), 11)
        self.assertEqual(counts.get("documents", 0), 4)

    def test_rejection_of_evidence_captured_after_audit_at(self):
        """Evidence captured strictly after audit_at is excluded."""
        # 2026-06-01 cutoff
        valid_june = self.engine.get_valid_evidence_files("2026-06-01T00:00:00Z")
        for meta in valid_june:
            self.assertLessEqual(meta.captured_at, "2026-06-01T00:00:00Z")

        # 2026-10-01 cutoff includes all or almost all
        valid_oct = self.engine.get_valid_evidence_files("2026-10-01T12:00:00Z")
        self.assertGreater(len(valid_oct), len(valid_june))

    def test_sql_snapshot_execution(self):
        """Execute SQLite snapshot on customer_accounts_failover_replica_20260902.sql."""
        sql_path = DATASET_DIR / "evidence/databases/customer_accounts_failover_replica_20260902.sql"
        if sql_path.exists():
            tables = self.engine.parse_sql_snapshot(sql_path)
            self.assertIn("customer_profiles_failover_replica", tables)
            self.assertIn("customer_profiles_primary", tables)

            # Check that account_005 is in failover replica but not in primary
            replica_rows = tables["customer_profiles_failover_replica"]
            primary_rows = tables["customer_profiles_primary"]

            replica_accounts = [r["resource_id"] for r in replica_rows]
            primary_accounts = [r["resource_id"] for r in primary_rows]

            self.assertIn("account_005", replica_accounts)
            self.assertNotIn("account_005", primary_accounts)

    def test_malformed_sql_handling(self):
        """Malformed SQL does not crash the parser."""
        with tempfile.NamedTemporaryFile("w", suffix=".sql", delete=False) as f:
            f.write("THIS IS NOT VALID SQL SYNTAX;")
            temp_path = Path(f.name)

        try:
            tables = self.engine.parse_sql_snapshot(temp_path)
            self.assertIn("_error", tables)
        finally:
            temp_path.unlink()

    def test_json_record_parsing(self):
        """Parse structured JSON evidence files."""
        json_path = DATASET_DIR / "evidence/records/connector_configurations_20260812.json"
        if json_path.exists():
            records = self.engine.parse_json_records(json_path)
            self.assertIsInstance(records, list)
            self.assertGreater(len(records), 0)

    def test_log_file_parsing(self):
        """Parse structured logs with key=value format."""
        log_path = DATASET_DIR / "evidence/logs/service_events_ap_south_20260915.log"
        if log_path.exists():
            entries = self.engine.parse_log_file(log_path)
            self.assertIsInstance(entries, list)
            self.assertGreater(len(entries), 0)

    def test_pdf_extraction_and_custom_font_flagging(self):
        """Verify delivery_correction_attachment.pdf extracts text and flags custom font."""
        pdf_path = DATASET_DIR / "evidence/documents/delivery_correction_attachment.pdf"
        if pdf_path.exists():
            res = self.engine.parse_pdf_text_streams(pdf_path)
            self.assertIn("extracted_text", res)
            self.assertIn("support_001", res["extracted_text"])
            self.assertIn("has_custom_font_cmap", res)

    def test_separation_of_event_time_from_evidence_capture_time(self):
        """Verify underlying record event timestamp is preserved separately from capture time."""
        sql_path = DATASET_DIR / "evidence/databases/customer_accounts_failover_replica_20260902.sql"
        if sql_path.exists():
            meta = self.engine.inventory.get("evidence_54")
            self.assertIsNotNone(meta)
            tables = self.engine.parse_sql_snapshot(sql_path)
            rows = tables.get("customer_profiles_failover_replica", [])
            self.assertGreater(len(rows), 0)
            rec = rows[0]
            # Capture time from manifest: 2026-09-02T23:00:00Z
            # Record updated_at inside SQL: 2026-09-02T22:45:00Z
            self.assertEqual(meta.captured_at, "2026-09-02T23:00:00Z")
            self.assertEqual(rec["updated_at"], "2026-09-02T22:45:00Z")
            self.assertNotEqual(meta.captured_at, rec["updated_at"])

    def test_malformed_json_and_log_handling(self):
        """Malformed JSON and logs do not crash parser and return empty structures."""
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write("{ INVALID JSON CONTENT : ")
            temp_json = Path(f.name)
        try:
            records = self.engine.parse_json_records(temp_json)
            self.assertEqual(records, [])
        finally:
            temp_json.unlink()

        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
            f.write("Some non-key-value unparseable string content\n\n")
            temp_log = Path(f.name)
        try:
            entries = self.engine.parse_log_file(temp_log)
            self.assertEqual(entries, [])
        finally:
            temp_log.unlink()

    def test_all_four_pdf_documents_extraction_status(self):
        """Verify all 4 PDFs are inspected and custom font subsetting is flagged."""
        doc_dir = DATASET_DIR / "evidence/documents"
        pdf_files = list(doc_dir.glob("*.pdf"))
        self.assertEqual(len(pdf_files), 4)

        for p in pdf_files:
            res = self.engine.parse_pdf_text_streams(p)
            self.assertIn("extracted_text", res)
            self.assertIn("has_custom_font_cmap", res)
            self.assertIn("is_potentially_incomplete", res)


if __name__ == "__main__":
    unittest.main()

