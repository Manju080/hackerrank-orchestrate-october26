"""Unit tests for Phase 2: Identity Resolution and Alias Tracking."""

import unittest
import tempfile
from pathlib import Path
import pandas as pd

from code.audit.identity import IdentityResolver, UserIdentity


class TestPhase2Identity(unittest.TestCase):
    """Test identity resolution with temporal boundaries and collision guards."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.identities_path = Path(self.temp_dir.name) / "test_user_identities.csv"
        self.audit_log_path = Path(self.temp_dir.name) / "test_user_audit_log.csv"

        # Create isolated test identities
        identities_df = pd.DataFrame([
            {
                "user_id": "user_100",
                "name": "Alice Smith",
                "email": "alice.new@example.com",
                "phone": "+1 555 0100",
                "email_hash": "hash_alice",
                "updated_at": "2026-06-01T10:00:00Z",
            },
            {
                "user_id": "user_200",
                "name": "Bob Jones",
                "email": "bob@example.com",
                "phone": "+1 555 0200",
                "email_hash": "hash_bob",
                "updated_at": "2026-06-01T10:00:00Z",
            },
            {
                "user_id": "user_300",
                "name": "Charlie Reuse",
                "email": "reused@example.com",
                "phone": "+1 555 0300",
                "email_hash": "hash_charlie",
                "updated_at": "2026-08-01T10:00:00Z",
            },
        ])
        identities_df.to_csv(self.identities_path, index=False)

        # Create isolated audit log
        audit_df = pd.DataFrame([
            {
                "audit_id": "audit_01",
                "user_id": "user_100",
                "event_time": "2026-05-15T09:00:00Z",
                "field_name": "email",
                "old_value": "alice.old@example.com",
                "new_value": "alice.new@example.com",
            },
            # Charlie previously used "reused@example.com" starting 2026-08-01.
            # Bob Jones used "reused@example.com" historically until 2026-04-01!
            {
                "audit_id": "audit_02",
                "user_id": "user_200",
                "event_time": "2026-04-01T08:00:00Z",
                "field_name": "email",
                "old_value": "reused@example.com",
                "new_value": "bob@example.com",
            },
        ])
        audit_df.to_csv(self.audit_log_path, index=False)

        self.resolver = IdentityResolver(
            identities_path=self.identities_path,
            audit_log_path=self.audit_log_path,
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_exact_matching_current_identifier(self):
        """Current email matches user_100 exactly."""
        user = self.resolver.resolve_by_email("alice.new@example.com")
        self.assertIsNotNone(user)
        self.assertEqual(user.user_id, "user_100")
        self.assertEqual(user.name, "Alice Smith")

    def test_resolution_of_historical_identifier(self):
        """Historical email resolves user_100."""
        user = self.resolver.resolve_by_email("alice.old@example.com")
        self.assertIsNotNone(user)
        self.assertEqual(user.user_id, "user_100")
        self.assertIn("alice.old@example.com", user.all_emails)

    def test_email_reuse_with_temporal_boundaries(self):
        """Reused email resolves Bob Jones before 2026-04-01 and Charlie after 2026-08-01."""
        # Request at 2026-03-01 belongs to Bob (user_200)
        user_march = self.resolver.resolve_by_email("reused@example.com", as_of_time="2026-03-01T00:00:00Z")
        self.assertIsNotNone(user_march)
        self.assertEqual(user_march.user_id, "user_200")

        # Request at 2026-09-01 belongs to Charlie (user_300)
        user_sept = self.resolver.resolve_by_email("reused@example.com", as_of_time="2026-09-01T00:00:00Z")
        self.assertIsNotNone(user_sept)
        self.assertEqual(user_sept.user_id, "user_300")

    def test_ambiguous_matches_without_false_merges(self):
        """Without a timestamp, an identifier reused across users does not cause a false merge."""
        user = self.resolver.resolve_by_email("reused@example.com", as_of_time=None)
        self.assertIsNone(user, "Should return None to avoid unsafe false merge")

    def test_case_insensitive_and_whitespace_handling(self):
        """Email matching is case-insensitive and trims whitespace."""
        user = self.resolver.resolve_by_email("  ALICE.NEW@EXAMPLE.COM ")
        self.assertIsNotNone(user)
        self.assertEqual(user.user_id, "user_100")

    def test_unknown_email_returns_none(self):
        user = self.resolver.resolve_by_email("nonexistent@example.com")
        self.assertIsNone(user)


if __name__ == "__main__":
    unittest.main()
