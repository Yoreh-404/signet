"""SQLite-only offline regression. No database file or migration runner."""
from pathlib import Path
import sqlite3
import unittest


class AuthorityStateTest(unittest.TestCase):
    def test_withdrawal_fences_stale_writers_and_survives_app_deletion(self):
        with sqlite3.connect(":memory:") as db:
            db.executescript(Path(__file__).with_name(
                "axon-admin-v2-tombstone.sql").read_text())
            db.execute("CREATE TABLE applications (slug TEXT PRIMARY KEY)")
            db.execute("INSERT INTO applications VALUES ('axon')")
            digest = "a" * 43
            replacement = "b" * 43
            db.execute(
                "INSERT INTO axon_admin_authority_state VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("tenant", "axon", "verified-enrollment", 3, digest, 1, 0),
            )

            def transition(old_generation, enrollment, expected_revision, expected_digest,
                           new_revision, new_digest, new_withdrawn, *,
                           local_disable=False, reapproved=False):
                return db.execute("""
                    UPDATE axon_admin_authority_state
                    SET revision = ?, digest = ?, generation = generation + 1,
                        withdrawn = ?
                    WHERE organization_id = 'tenant' AND application_slug = 'axon'
                      AND enrollment_id = ?
                      AND generation = ? AND revision = ? AND digest = ?
                      AND ((? > revision AND (withdrawn = 0 OR ? = 1 OR ? = 1))
                           OR (? = 1 AND ? = revision AND ? = digest
                               AND ? = 1 AND withdrawn = 0))
                    """, (new_revision, new_digest, new_withdrawn, enrollment,
                          old_generation, expected_revision, expected_digest,
                          new_revision, new_withdrawn, reapproved, local_disable,
                          new_revision, new_digest, new_withdrawn)).rowcount

            self.assertEqual(transition(1, "verified-enrollment", 3, digest, 3, digest, 1), 0)
            self.assertEqual(transition(1, "verified-enrollment", 3, digest, 3, digest, 1,
                                        local_disable=True), 1)
            db.execute("DELETE FROM applications WHERE slug = 'axon'")
            db.execute("INSERT INTO applications VALUES ('axon')")
            self.assertEqual(transition(1, "verified-enrollment", 3, digest, 4, replacement, 0), 0)
            self.assertEqual(transition(2, "verified-enrollment", 3, digest, 3, digest, 0), 0)
            self.assertEqual(transition(2, "replacement-enrollment", 3, digest, 4, replacement, 0), 0)
            self.assertEqual(transition(2, "verified-enrollment", 3, digest, 4, replacement, 0), 0)
            self.assertEqual(transition(2, "verified-enrollment", 3, digest, 4, replacement, 0,
                                        reapproved=True), 1)
            self.assertEqual(db.execute(
                "SELECT revision, generation, withdrawn FROM axon_admin_authority_state"
            ).fetchone(), (4, 3, 0))


if __name__ == "__main__":
    unittest.main()
