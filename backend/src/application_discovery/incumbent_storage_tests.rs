//! Inert storage proof only: no migration, CLI, or production reader.
use diesel::{Connection, RunQueryDsl, SqliteConnection, sql_query,
    sql_types::{BigInt, Text}};

use diesel::connection::SimpleConnection;

const SCHEMA: &str = "CREATE TABLE axon_v3_incumbent_activation (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    profile TEXT NOT NULL CHECK (profile = 'incumbent_v1'),
    application_db_id TEXT NOT NULL,
    client_db_id TEXT NOT NULL,
    organization_id TEXT NOT NULL,
    enrollment_id TEXT NOT NULL,
    host_sha256 TEXT NOT NULL,
    signer_pin TEXT NOT NULL,
    policy_sha256 TEXT NOT NULL,
    policy_json TEXT NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
    generation BIGINT NOT NULL CHECK (generation > 0),
    withdrawn INTEGER NOT NULL CHECK (withdrawn IN (0, 1))
)";

#[derive(Clone, Copy)]
struct Version<'a> { digest: &'a str, revision: i64, generation: i64 }

fn replace(
    db: &mut SqliteConnection, expected: Version<'_>, next: Version<'_>,
    initial_marker: Option<u64>, current_marker: impl FnOnce() -> Option<u64>,
) -> diesel::QueryResult<()> {
    let Some(initial_marker) = initial_marker else { return Err(diesel::result::Error::RollbackTransaction); };
    db.transaction(|db| {
        let changed = sql_query("UPDATE axon_v3_incumbent_activation
            SET policy_sha256 = ?, policy_json = ?, revision = ?, generation = ?, withdrawn = 0
            WHERE singleton = 1 AND profile = 'incumbent_v1'
            AND policy_sha256 = ? AND revision = ? AND generation = ?
            AND revision < ? AND generation < ?")
            .bind::<Text, _>(next.digest)
            .bind::<Text, _>(format!(r#"{{"fixture_version":{}}}"#, next.revision))
            .bind::<BigInt, _>(next.revision).bind::<BigInt, _>(next.generation)
            .bind::<Text, _>(expected.digest)
            .bind::<BigInt, _>(expected.revision).bind::<BigInt, _>(expected.generation)
            .bind::<BigInt, _>(next.revision).bind::<BigInt, _>(next.generation)
            .execute(db)?;
        if changed != 1 || current_marker() != Some(initial_marker) {
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
