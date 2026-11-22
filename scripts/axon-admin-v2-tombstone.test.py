"""SQLite-only offline regression. No database file or migration runner."""
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest


class AuthorityStateTest(unittest.TestCase):
    def test_signed_reduction_requires_pre_advanced_halted_marker(self):
        with sqlite3.connect(":memory:") as current, sqlite3.connect(":memory:") as old_backup:
            current.executescript(Path(__file__).with_name("axon-admin-v2-tombstone.sql").read_text())
            old_digest, withdrawal_digest = "a" * 43, "b" * 43
            current.execute("""INSERT INTO axon_admin_authority_state
                (organization_id,application_slug,enrollment_id,revision,digest,generation,withdrawn,snapshot_json,expires_at)
                VALUES ('tenant','axon','enrollment',3,?,1,0,'{}',100)""", (old_digest,))
            current.commit()
            current.backup(old_backup)

            def withdraw(floor_generation, floor_revision, floor_digest, halted):
                if not halted or floor_revision != 4 or floor_digest != withdrawal_digest:
                    return False
                return current.execute("""UPDATE axon_admin_authority_state
                    SET revision=4, digest=?, withdrawn=1, generation=generation+1,
                        snapshot_json=NULL, expires_at=NULL
                    WHERE revision<4 AND withdrawn=0 AND generation=?""",
                    (withdrawal_digest, floor_generation-1)).rowcount == 1

            self.assertFalse(withdraw(1, 3, old_digest, False))
            self.assertFalse(withdraw(2, 4, withdrawal_digest, False))
            self.assertFalse(withdraw(3, 4, withdrawal_digest, True))
            self.assertTrue(withdraw(2, 4, withdrawal_digest, True))
            self.assertEqual(current.execute("SELECT revision,generation,withdrawn FROM axon_admin_authority_state").fetchone(),
                             (4, 2, 1))
            # Old config's revision 3/digest fails external revision 4/digest
            # equality, and even a mistaken unhalt cannot match the restored row.
            self.assertIsNone(old_backup.execute("""SELECT 1 FROM axon_admin_authority_state
                WHERE revision=4 AND digest=? AND generation>=2 AND withdrawn=0""",
                (withdrawal_digest,)).fetchone())

    def test_sqlite_restore_cannot_clear_independent_generation_floor(self):
        with tempfile.TemporaryDirectory() as anchor_dir, \
                tempfile.TemporaryDirectory() as backup_dir, \
                sqlite3.connect(":memory:") as current, \
                sqlite3.connect(Path(backup_dir) / "old.sqlite") as backup:
            marker = Path(anchor_dir) / "floor.json"
            current.executescript(Path(__file__).with_name("axon-admin-v2-tombstone.sql").read_text())
            digest = "a" * 43
            current.execute("""INSERT INTO axon_admin_authority_state
                (organization_id,application_slug,enrollment_id,revision,digest,generation,withdrawn,snapshot_json,expires_at)
                VALUES ('tenant','axon','enrollment',3,?,1,0,'{}',100)""", (digest,))
            current.commit()
            current.backup(backup)
            current.execute("""UPDATE axon_admin_authority_state SET withdrawn=1, generation=2,
                               snapshot_json=NULL, expires_at=NULL""")

            def authorizes(db, generation, halted):
                marker.write_text(json.dumps({"minimum_generation": generation, "halted": halted}))
                retained = json.loads(marker.read_text())
                return not retained["halted"] and db.execute("""SELECT 1 FROM axon_admin_authority_state
                    WHERE organization_id='tenant' AND application_slug='axon' AND enrollment_id='enrollment'
                    AND revision=3 AND digest=? AND generation>=? AND withdrawn=0 AND expires_at>50""",
                    (digest, retained["minimum_generation"])).fetchone() is not None

            self.assertTrue(authorizes(backup, 1, False))
            self.assertFalse(authorizes(current, 2, True))
            self.assertFalse(authorizes(backup, 2, True))
            self.assertFalse(authorizes(backup, 2, False))

    def test_generation_and_snapshot_commit_or_fail_together(self):
        with sqlite3.connect(":memory:") as db:
            db.executescript(Path(__file__).with_name(
                "axon-admin-v2-tombstone.sql").read_text())
            db.execute("""INSERT INTO axon_admin_authority_state
                (organization_id, application_slug, enrollment_id, revision, digest, generation, withdrawn)
                VALUES ('tenant','axon','enrollment',1,?,1,0)""", ("a"*43,))
            update = """UPDATE axon_admin_authority_state
                SET revision = ?, digest = ?, generation = generation+1, snapshot_json = ?, expires_at = ?
                WHERE organization_id = ? AND application_slug = 'axon' AND enrollment_id = 'enrollment'
                  AND generation = ? AND revision < ? AND withdrawn = 0"""
            fields = (2, "b"*43, '{"revision":2}', 120)
            self.assertEqual(db.execute(update, (*fields, "wrong", 1, 2)).rowcount, 0)
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute(update, (*fields[:3], None, "tenant", 1, 2))
            state = "SELECT revision, generation, snapshot_json FROM axon_admin_authority_state"
            self.assertEqual(db.execute(state).fetchone(), (1, 1, None))
            self.assertEqual(db.execute(update, (*fields, "tenant", 1, 2)).rowcount, 1)
            self.assertEqual(db.execute(state).fetchone(), (2, 2, '{"revision":2}'))

    def test_withdrawal_fences_stale_writers_and_survives_app_deletion(self):
        with sqlite3.connect(":memory:") as db:
            db.executescript(Path(__file__).with_name(
                "axon-admin-v2-tombstone.sql").read_text())
            db.execute("CREATE TABLE applications (slug TEXT PRIMARY KEY)")
            db.execute("INSERT INTO applications VALUES ('axon')")
            digest = "a" * 43
            replacement = "b" * 43
            db.execute(
                "INSERT INTO axon_admin_authority_state (organization_id, application_slug, enrollment_id, revision, digest, generation, withdrawn) VALUES (?, ?, ?, ?, ?, ?, ?)",
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
