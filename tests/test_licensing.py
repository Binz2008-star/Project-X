import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from project_x import LicenseError, LicenseStore

NOW = datetime(2026, 11, 20, 10, 0, tzinfo=timezone.utc)


class LicenseStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = LicenseStore(Path(self.tmp.name) / "licenses.db")
        self.store.register_product("demo.featurepack", "approved")

    def test_unapproved_product_is_blocked(self):
        self.store.register_product("instagram.plus")
        with self.assertRaises(LicenseError):
            self.store.issue_code("instagram.plus", "monthly")
        with self.assertRaises(LicenseError):
            self.store.start_trial("instagram.plus", "device", now=NOW)

    def test_seven_day_trial_only_once(self):
        self.assertEqual(
            self.store.start_trial("demo.featurepack", "device", now=NOW),
            "2026-11-27T10:00:00+00:00",
        )
        self.assertTrue(self.store.entitlement("demo.featurepack", "device", now=NOW)["active"])
        with self.assertRaises(LicenseError):
            self.store.start_trial("demo.featurepack", "device", now=NOW)
        expiry = datetime(2026, 11, 27, 10, 0, tzinfo=timezone.utc)
        self.assertFalse(self.store.entitlement("demo.featurepack", "device", now=expiry)["active"])

    def test_code_redeems_once_for_one_installation(self):
        code = self.store.issue_code("demo.featurepack", "monthly")
        self.assertEqual(len(code) >= 30, True)
        self.assertEqual(self.store.redeem(code, "a", now=NOW), "2026-12-20T10:00:00+00:00")
        with self.assertRaises(LicenseError):
            self.store.redeem(code, "b", now=NOW)
        self.assertTrue(self.store.entitlement("demo.featurepack", "a", now=NOW)["active"])
        self.assertFalse(self.store.entitlement("demo.featurepack", "b", now=NOW)["active"])

    def test_quarterly_and_renewal_stacking(self):
        first = self.store.issue_code("demo.featurepack", "quarterly")
        self.assertEqual(self.store.redeem(first, "a", now=NOW), "2027-02-20T10:00:00+00:00")
        next_code = self.store.issue_code("demo.featurepack", "monthly")
        self.assertEqual(self.store.redeem(next_code, "a", now=NOW), "2027-03-20T10:00:00+00:00")

    def test_month_end_clamping(self):
        jan_31 = datetime(2027, 1, 31, 8, tzinfo=timezone.utc)
        code = self.store.issue_code("demo.featurepack", "monthly")
        self.assertEqual(self.store.redeem(code, "a", now=jan_31), "2027-02-28T08:00:00+00:00")

    def test_invalid_plan_and_unknown_code(self):
        with self.assertRaises(LicenseError):
            self.store.issue_code("demo.featurepack", "weekly")
        with self.assertRaises(LicenseError):
            self.store.redeem("nonsense", "device", now=NOW)

    def test_revoking_approval_blocks_access(self):
        code = self.store.issue_code("demo.featurepack", "monthly")
        self.store.redeem(code, "a", now=NOW)
        self.store.register_product("demo.featurepack", "blocked")
        self.assertFalse(self.store.entitlement("demo.featurepack", "a", now=NOW)["active"])


if __name__ == "__main__":
    unittest.main()
