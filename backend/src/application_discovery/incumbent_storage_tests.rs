//! Inert storage proof only: no migration, CLI, or production reader.
use diesel::{Connection, RunQueryDsl, SqliteConnection, sql_query,
    sql_types::{BigInt, Text}};

use diesel::connection::SimpleConnection;
use crate::db::axon_v3_incumbent_storage::{SCHEMA, Version};

fn replace(
    db: &mut SqliteConnection, expected: Version<'_>, next: Version<'_>,
    initial_marker: Option<u64>, current_marker: impl FnOnce() -> Option<u64>,
) -> diesel::QueryResult<()> {
    let Some(initial_marker) = initial_marker else { return Err(diesel::result::Error::RollbackTransaction); };
    let bytes = format!(r#"{{"fixture_version":{}}}"#, next.revision);
    replace_checked(db, expected, next, &bytes, || current_marker() == Some(initial_marker))
}

fn replace_checked(
    db: &mut SqliteConnection, expected: Version<'_>, next: Version<'_>,
    bytes: &str, restore_unchanged: impl FnOnce() -> bool,
) -> diesel::QueryResult<()> {
    db.transaction(|db| {
        let changed = sql_query("UPDATE axon_v3_incumbent_activation
            SET policy_sha256 = ?, policy_json = ?, revision = ?, generation = ?, withdrawn = 0
            WHERE singleton = 1 AND profile = 'incumbent_v1'
            AND policy_sha256 = ? AND revision = ? AND generation = ?
            AND revision < ? AND generation < ?")
            .bind::<Text, _>(next.digest)
            .bind::<Text, _>(bytes)
            .bind::<BigInt, _>(next.revision).bind::<BigInt, _>(next.generation)
            .bind::<Text, _>(expected.digest)
            .bind::<BigInt, _>(expected.revision).bind::<BigInt, _>(expected.generation)
            .bind::<BigInt, _>(next.revision).bind::<BigInt, _>(next.generation)
            .execute(db)?;
        if changed != 1 || !restore_unchanged() {
            return Err(diesel::result::Error::RollbackTransaction);
        }
        Ok(())
    })
}

fn withdraw(db: &mut SqliteConnection, expected: Version<'_>) -> diesel::QueryResult<usize> {
    sql_query("UPDATE axon_v3_incumbent_activation SET withdrawn = 1
        WHERE singleton = 1 AND profile = 'incumbent_v1' AND withdrawn = 0
        AND policy_sha256 = ? AND revision = ? AND generation = ?")
        .bind::<Text, _>(expected.digest)
        .bind::<BigInt, _>(expected.revision).bind::<BigInt, _>(expected.generation)
        .execute(db)
}

#[test]
fn axon_v3_incumbent_storage_is_singleton_and_cas_does_not_resurrect_withdrawal() {
    let mut db = SqliteConnection::establish(":memory:").unwrap();
    db.batch_execute(SCHEMA).unwrap();
    let seed = |db: &mut SqliteConnection, id, profile| sql_query(
        "INSERT INTO axon_v3_incumbent_activation
        VALUES (?, ?, 'app', 'client', 'org', 'enrollment', 'host', 'signer', 'a', '{}', 1, 1, 0)")
        .bind::<diesel::sql_types::Integer, _>(id).bind::<Text, _>(profile).execute(db);
    assert!(seed(&mut db, 2, "incumbent_v1").is_err());
    assert!(seed(&mut db, 1, "managed").is_err());
    assert_eq!(seed(&mut db, 1, "incumbent_v1").unwrap(), 1);
    assert!(seed(&mut db, 1, "incumbent_v1").is_err());

    let a = Version { digest: "a", revision: 1, generation: 1 };
    let b = Version { digest: "b", revision: 2, generation: 2 };
    let marker = std::cell::Cell::new(Some(10));
    assert!(replace(&mut db, a, b, marker.get(), || { marker.set(None); marker.get() }).is_err());
    assert!(replace(&mut db, a, b, marker.get(), || Some(11)).is_err(), "held");
    assert_eq!(withdraw(&mut db, b).unwrap(), 0, "failed transaction did not publish");
    assert_eq!(withdraw(&mut db, a).unwrap(), 1, "withdrawal is permitted while held");
    marker.set(Some(11));
    assert!(replace(&mut db, a, a, marker.get(), || marker.get()).is_err());
    assert_eq!(withdraw(&mut db, a).unwrap(), 0, "reopen did not clear the tombstone");
    assert!(replace(&mut db, a, b, marker.get(), || Some(12)).is_err(), "marker replaced");
    assert!(replace(&mut db, Version { digest: "foreign", ..a }, b, marker.get(), || marker.get()).is_err());
    assert!(replace(&mut db, Version { revision: 2, ..a }, b, marker.get(), || marker.get()).is_err());
    assert!(replace(&mut db, Version { generation: 2, ..a }, b, marker.get(), || marker.get()).is_err());
    assert!(replace(&mut db, a, Version { revision: 1, ..b }, marker.get(), || marker.get()).is_err());
    assert!(replace(&mut db, a, Version { generation: 1, ..b }, marker.get(), || marker.get()).is_err());
    replace(&mut db, a, b, marker.get(), || marker.get()).unwrap();
    assert_eq!(withdraw(&mut db, a).unwrap(), 0);
    assert_eq!(withdraw(&mut db, b).unwrap(), 1);
}

/// Called only by the exact synthetic enrollment test after preflight has
/// matched the real session, current registry and enrolled signer.
#[cfg(all(target_os = "linux", feature = "axon-incumbent-storage"))]
pub(crate) fn signed_file_bench(
    fixture_path: &std::path::Path,
    pin: &super::incumbent_preflight::IncumbentPin<'_>,
    approved: &super::axon_v3_acceptance::VerifiedPolicy,
    replacement: &super::axon_v3_acceptance::VerifiedPolicy,
) {
    use crate::db::axon_v3_incumbent_storage::RestoreSnapshot;
    use super::axon_v3_restore::RestoreInterlock;
    use std::{fs, os::unix::fs::{DirBuilderExt, PermissionsExt}};

    let root = fixture_path.with_extension("incumbent-private");
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let ledger = root.join("fixture.sqlite3");
    let marker_root = root.join("restore");
    fs::create_dir(&marker_root).unwrap();
    let marker = marker_root.join("current.json");
    let open = || SqliteConnection::establish(ledger.to_str().unwrap()).unwrap();
    let set_gate = |ready: bool| {
        fs::set_permissions(&marker_root, fs::Permissions::from_mode(0o700)).unwrap();
        let pending = marker_root.join("next");
        fs::write(&pending, serde_json::json!({"format":"signet-privileged-restore/v1",
            "state":if ready {"reconciled"} else {"held"},
            "operation_id":uuid::Uuid::new_v4()}).to_string()).unwrap();
        fs::set_permissions(&pending, fs::Permissions::from_mode(0o400)).unwrap();
        fs::rename(pending, &marker).unwrap();
        fs::set_permissions(&marker_root, fs::Permissions::from_mode(0o500)).unwrap();
    };
    let gate = RestoreInterlock::new(marker.clone(), rustix::process::geteuid().as_raw());
    let mut conn = open();
    conn.batch_execute(SCHEMA).unwrap();
    let a = Version { digest: approved.sha256(), revision: pin.revision, generation: pin.generation };
    let b = Version { digest: replacement.sha256(), revision: replacement.policy().revision,
        generation: replacement.policy().generation };
    let insert = |conn: &mut SqliteConnection| -> diesel::QueryResult<()> {
        let snapshot = RestoreSnapshot::capture(&gate).ok_or(diesel::result::Error::RollbackTransaction)?;
        conn.transaction(|conn| {
            let changed = sql_query("INSERT INTO axon_v3_incumbent_activation
                SELECT 1, 'incumbent_v1', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0
                WHERE NOT EXISTS (SELECT 1 FROM axon_v3_incumbent_activation WHERE singleton = 1)")
                .bind::<Text, _>(pin.application_db_id).bind::<Text, _>(pin.client_db_id)
                .bind::<Text, _>(&approved.policy().organization_id)
                .bind::<Text, _>(&approved.policy().enrollment_id)
                .bind::<Text, _>(pin.host_sha256).bind::<Text, _>(pin.signer_pin)
                .bind::<Text, _>(a.digest).bind::<Text, _>(approved.bytes())
                .bind::<BigInt, _>(a.revision).bind::<BigInt, _>(a.generation)
                .execute(conn)?;
            if changed != 1 || !snapshot.unchanged() {
                return Err(diesel::result::Error::RollbackTransaction);
            }
            Ok(())
        })
    };
    assert!(insert(&mut conn).is_err(), "missing real marker");
    set_gate(true);
    insert(&mut conn).unwrap();
    assert!(insert(&mut conn).is_err(), "first activation expects no row");
    let snapshot = RestoreSnapshot::capture(&gate).unwrap();
    assert!(replace_checked(&mut conn, a, b, replacement.bytes(), || {
        set_gate(true);
        snapshot.unchanged()
    }).is_err(), "marker replacement rolls back SQL");
    set_gate(false);
    assert!(RestoreSnapshot::capture(&gate).is_none());
    assert_eq!(withdraw(&mut conn, b).unwrap(), 0);
    assert_eq!(withdraw(&mut conn, a).unwrap(), 1, "withdrawal works while held");
    drop(conn);
    set_gate(true);
    let mut conn = open();
    let snapshot = RestoreSnapshot::capture(&gate).unwrap();
    assert_eq!(withdraw(&mut conn, a).unwrap(), 0, "reopen retains exact tombstone");
    assert!(replace_checked(&mut conn, a, a, approved.bytes(), || snapshot.unchanged()).is_err());
    assert!(replace_checked(&mut conn, b, b, replacement.bytes(), || snapshot.unchanged()).is_err());
    replace_checked(&mut conn, a, b, replacement.bytes(), || snapshot.unchanged()).unwrap();
    assert_eq!(withdraw(&mut conn, a).unwrap(), 0, "old command cannot affect new digest");
    assert_eq!(withdraw(&mut conn, b).unwrap(), 1);
    drop(conn);
    fs::set_permissions(&marker_root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::remove_dir_all(root).unwrap();
}
