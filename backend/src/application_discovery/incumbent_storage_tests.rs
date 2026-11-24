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
        VALUES (?, ?, 'app', 'client', 'org', 'enrollment', 'signer', 'a', '{}', 1, 1, 0)")
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
    foreign: &super::axon_v3_acceptance::VerifiedPolicy,
    enrolled_jwks: &str,
) {
    use crate::db::axon_v3_incumbent_storage::{RestoreSnapshot, sqlite};
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
    let next_pin = super::incumbent_preflight::IncumbentPin {
        policy_sha256: b.digest, revision: b.revision, generation: b.generation, ..*pin
    };
    let insert = |conn: &mut SqliteConnection, approved| {
        sqlite::compare_and_set(conn, &gate, pin, enrolled_jwks, None, approved)
    };
    assert!(insert(&mut conn, approved).is_err(), "missing real marker");
    set_gate(true);
    assert!(insert(&mut conn, foreign).is_err(), "valid but non-enrolled signer");
    insert(&mut conn, approved).unwrap();
    assert!(insert(&mut conn, approved).is_err(), "first activation expects no row");
    assert!(sqlite::compare_and_set_with_test_hook(&mut conn, &gate, &next_pin, enrolled_jwks,
        Some(a), replacement, || set_gate(true)).is_err(), "marker replacement rolls back SQL");
    set_gate(false);
    assert!(RestoreSnapshot::capture(&gate).is_none());
    assert_eq!(sqlite::withdraw(&mut conn, &next_pin).unwrap(), 0);
    assert_eq!(sqlite::withdraw(&mut conn, pin).unwrap(), 1, "withdrawal works while held");
    drop(conn);
    set_gate(true);
    let mut conn = open();
    assert_eq!(sqlite::withdraw(&mut conn, pin).unwrap(), 0, "reopen retains exact tombstone");
    assert!(sqlite::compare_and_set(&mut conn, &gate, pin, enrolled_jwks, Some(a), approved).is_err());
    assert!(sqlite::compare_and_set(&mut conn, &gate, &next_pin, enrolled_jwks, Some(b), replacement).is_err());
    let foreign_app = super::incumbent_preflight::IncumbentPin { application_db_id: "foreign", ..next_pin };
    assert!(sqlite::compare_and_set(&mut conn, &gate, &foreign_app, enrolled_jwks, Some(a), replacement).is_err());
    sqlite::compare_and_set(&mut conn, &gate, &next_pin, enrolled_jwks, Some(a), replacement).unwrap();
    assert_eq!(sqlite::withdraw(&mut conn, pin).unwrap(), 0, "old command cannot affect new digest");
    assert_eq!(sqlite::withdraw(&mut conn, &next_pin).unwrap(), 1);
    drop(conn);

    // Use the actual migrated registry (not the storage-only database above)
    // with the same enrolled test JWKS and signed VerifiedPolicy.
    let p = approved.policy();
    let enrolled = crate::config::AxonAdminV3Enrollment {
        organization_id: p.organization_id.clone(), enrollment_id: p.enrollment_id.clone(),
        application_id: p.application_id.clone(), issuer: p.issuer.clone(),
        client_id: p.client_id.clone(), introspection_client_id: "not-used-by-writer".into(),
        audience: p.audience.clone(), origin: p.origin.clone(),
        restore_marker_path: marker.clone(), restore_marker_owner_uid: rustix::process::geteuid().as_raw(),
    };
    let trust = crate::config::AxonAdminTrust {
        organization_id: p.organization_id.clone(), application_id: p.application_id.clone(),
        client_id: p.client_id.clone(), audience: p.audience.clone(), origin: p.origin.clone(),
        signing_public_jwks: enrolled_jwks.into(),
    };
    let registry = || SqliteConnection::establish(fixture_path.to_str().unwrap()).unwrap();
    let mut registry_conn = registry();
    registry_conn.batch_execute(SCHEMA).unwrap();
    assert!(sqlite::write_enrolled_incumbent(&mut registry_conn, &enrolled, &trust, None, foreign).is_err());
    let wrong_site = crate::config::AxonAdminTrust { origin: "https://foreign.example".into(), ..trust.clone() };
    assert!(sqlite::write_enrolled_incumbent(&mut registry_conn, &enrolled, &wrong_site, None, approved).is_err());
    assert!(sqlite::write_enrolled_incumbent_with_test_hook(
        &mut registry_conn, &enrolled, &trust, None, approved, || set_gate(true))
        .is_err(), "replacement marker invalidates the entire transaction, including its savepoint");
    let mut competing = registry();
    let disable_site = |conn: &mut SqliteConnection| sql_query(
        "UPDATE application_discovery SET operator_disabled=1 WHERE application_id=?")
        .bind::<Text,_>(pin.application_db_id).execute(conn);
    sqlite::write_enrolled_incumbent_with_test_hook(&mut registry_conn, &enrolled, &trust, None, approved, || {
        competing.batch_execute("PRAGMA busy_timeout=0;").unwrap();
        let rejected = disable_site(&mut competing).unwrap_err();
        assert!(rejected.to_string().contains("database is locked"), "{rejected}");
    }).unwrap();
    #[derive(diesel::QueryableByName)]
    struct Saved {
        #[diesel(sql_type = Text)] application_db_id: String,
        #[diesel(sql_type = Text)] client_db_id: String,
        #[diesel(sql_type = Text)] policy_sha256: String,
        #[diesel(sql_type = Text)] signer_pin: String,
    }
    let saved = |conn: &mut SqliteConnection| sql_query("SELECT application_db_id, client_db_id,
        policy_sha256, signer_pin FROM axon_v3_incumbent_activation WHERE singleton=1")
        .get_result::<Saved>(conn).unwrap();
    drop(registry_conn);
    let written = saved(&mut registry());
    assert_eq!((written.application_db_id.as_str(), written.client_db_id.as_str(),
        written.policy_sha256.as_str(), written.signer_pin.as_str()),
        (pin.application_db_id, pin.client_db_id, approved.sha256(), pin.signer_pin));
    let active = |pin, proof| registry().immediate_transaction(|conn|
        sqlite::exact_active_policy(conn, &gate, pin, proof)).unwrap();
    assert!(active(pin, approved));
    let rotated = registry().immediate_transaction::<(), diesel::result::Error, _>(|conn| {
        sql_query("UPDATE application_discovery SET signing_public_jwks='{}' WHERE application_id=?")
            .bind::<Text,_>(pin.application_db_id).execute(conn)?;
        assert!(!sqlite::exact_active_policy(conn, &gate, pin, approved)?,
            "unchanged ledger cannot authorize with a different current registry signer");
        Err(diesel::result::Error::RollbackTransaction)
    });
    assert!(matches!(rotated, Err(diesel::result::Error::RollbackTransaction)));
    assert!(active(pin, approved), "rollback restores exact enrolled authority");
    assert!(!active(pin, foreign));
    assert!(!active(&next_pin, replacement));
    assert_eq!(disable_site(&mut competing).unwrap(), 1, "write is possible after the incumbent transaction");
    assert!(!active(pin, approved), "unchanged ledger cannot authorize a disabled site");
    assert!(sqlite::write_enrolled_incumbent(&mut registry(), &enrolled, &trust, Some(a), replacement).is_err());
    assert_eq!(saved(&mut registry()).policy_sha256, approved.sha256());
    sql_query("UPDATE application_discovery SET operator_disabled=0 WHERE application_id=?")
        .bind::<Text,_>(pin.application_db_id).execute(&mut competing).unwrap();
    set_gate(false);
    assert!(!active(pin, approved));
    assert!(sqlite::write_enrolled_incumbent(&mut registry(), &enrolled, &trust, Some(a), replacement).is_err());
    assert_eq!(saved(&mut registry()).policy_sha256, approved.sha256());
    set_gate(true);
    sqlite::write_enrolled_incumbent(&mut registry(), &enrolled, &trust, Some(a), replacement).unwrap();
    assert_eq!(saved(&mut registry()).policy_sha256, replacement.sha256());
    assert!(active(&next_pin, replacement));
    assert!(!active(pin, approved));
    assert_eq!(sqlite::withdraw(&mut registry(), &next_pin).unwrap(), 1);
    assert!(!active(&next_pin, replacement));

    fs::set_permissions(&marker_root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::remove_dir_all(root).unwrap();
}
