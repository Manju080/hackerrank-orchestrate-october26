"""test_phase4_benchmark.py - Regression testing for Phase 4 benchmark and custom cases."""

import unittest
from code.audit.policy_engine import PolicyEngine
from code.audit.planner import RemediationPlanner
from code.evaluation.custom_cases import run_custom_cases, get_custom_test_cases


class TestPhase4Benchmark(unittest.TestCase):

    def setUp(self):
        self.policy_engine = PolicyEngine()
        self.planner = RemediationPlanner()

    def test_custom_cases_fixture_generation(self):
        """Verify the 3 independent custom evaluation fixtures are fully formed."""
        cases = get_custom_test_cases()
        self.assertEqual(len(cases), 3)
        case_ids = [c.case_id for c in cases]
        self.assertEqual(case_ids, ["custom_case_01", "custom_case_02", "custom_case_03"])

    def test_custom_cases_execution_and_accuracy(self):
        """Execute custom cases through production policy and planning pipeline."""
        res = run_custom_cases(self.policy_engine, self.planner)
        self.assertEqual(res["total_cases"], 3)
        self.assertEqual(res["status_accuracy"], 1.0)
        self.assertEqual(res["exact_steps_accuracy"], 1.0)
        for c in res["cases"]:
            self.assertTrue(c["status_match"], f"Status mismatch in {c['case_id']}")
            self.assertTrue(c["steps_match"], f"Steps mismatch in {c['case_id']}")


if __name__ == "__main__":
    unittest.main()
