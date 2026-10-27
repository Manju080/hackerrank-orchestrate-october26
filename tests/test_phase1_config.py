"""Unit tests for Phase 1: Configuration, Prompts, and Token Tracking."""

import unittest
from pathlib import Path
from code.config import (
    REPO_ROOT,
    DATASET_DIR,
    PROMPTS_DIR,
    ALLOWED_STATUSES,
    ALLOWED_PHASES,
    OPERATION_STATE_MAPPING,
    CANONICAL_OPERATION_ORDER,
    STEP_KEYS,
)
from code.utils.prompt_loader import prompt_loader
from code.utils.token_tracker import TokenTracker, ModelPricing


class TestPhase1Config(unittest.TestCase):
    """Test official contract definitions and configuration paths."""

    def test_repository_paths_exist(self):
        """Verify repository paths resolve to actual disk directories."""
        self.assertTrue(REPO_ROOT.exists(), "REPO_ROOT must exist")
        self.assertTrue(DATASET_DIR.exists(), "DATASET_DIR must exist")
        self.assertTrue(PROMPTS_DIR.exists(), "PROMPTS_DIR must exist")

    def test_contract_enums(self):
        """Verify allowed statuses, phases, and operation-state mappings."""
        self.assertEqual(ALLOWED_STATUSES, {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"})
        self.assertEqual(ALLOWED_PHASES, ["FINDING", "REMEDIATION", "VERIFICATION"])
        self.assertEqual(len(OPERATION_STATE_MAPPING), 15)

        for phase in ALLOWED_PHASES:
            self.assertIn(phase, CANONICAL_OPERATION_ORDER)
            ops = CANONICAL_OPERATION_ORDER[phase]
            for op in ops:
                self.assertIn(op, OPERATION_STATE_MAPPING)

    def test_step_schema_keys(self):
        """Verify step schema keys match problem statement."""
        expected = [
            "step_no",
            "phase",
            "system_id",
            "resource_id",
            "operation",
            "state",
            "evidence_id",
        ]
        self.assertEqual(STEP_KEYS, expected)


class TestPromptLoader(unittest.TestCase):
    """Test loading and interpolation of Markdown prompt templates."""

    def test_load_intent_classification_prompt(self):
        rendered = prompt_loader.render_prompt(
            "intent_classification.md",
            case_id="case_test_01",
            request_text="Please delete my account immediately.",
        )
        self.assertIn("case_test_01", rendered)
        self.assertIn("Please delete my account immediately.", rendered)
        self.assertIn("authorizes_deletion", rendered)

    def test_load_evidence_extraction_prompt(self):
        rendered = prompt_loader.render_prompt(
            "evidence_extraction.md",
            file_id="evidence_test_01",
            origin="test_service",
            captured_at="2026-09-01T12:00:00Z",
        )
        self.assertIn("evidence_test_01", rendered)
        self.assertIn("test_service", rendered)
        self.assertIn("extracted_records", rendered)

    def test_missing_prompt_raises(self):
        with self.assertRaises(FileNotFoundError):
            prompt_loader.load_prompt("non_existent_prompt.md")


class TestTokenTracker(unittest.TestCase):
    """Test token usage and cost accounting without external calls."""

    def test_record_call_and_summary(self):
        pricing = {"test-model": ModelPricing(prompt_price_per_1m=1.00, completion_price_per_1m=2.00)}
        tracker = TokenTracker(pricing_table=pricing)

        # 10,000 prompt tokens ($0.01) + 5,000 completion tokens ($0.01) = $0.02
        call = tracker.record_call(
            provider="test-provider",
            model="test-model",
            input_tokens=10000,
            output_tokens=5000,
            case_id="case_01",
            task_name="test_task",
        )
        self.assertAlmostEqual(call.estimated_cost, 0.02, places=4)

        summary = tracker.get_summary(total_cases=2)
        self.assertEqual(summary["total_calls"], 1)
        self.assertEqual(summary["total_input_tokens"], 10000)
        self.assertEqual(summary["total_output_tokens"], 5000)
        self.assertEqual(summary["total_tokens"], 15000)
        self.assertAlmostEqual(summary["total_cost"], 0.02, places=4)
        self.assertAlmostEqual(summary["average_tokens_per_request"], 7500.0)

        report = tracker.generate_markdown_report(total_cases=2)
        self.assertIn("test-model", report)
        self.assertIn("$0.0200", report)


if __name__ == "__main__":
    unittest.main()
