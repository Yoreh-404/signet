// Compiles only as a conformance test. No production deserializer uses this type.
use serde::Deserialize;

const RESERVED_CLAIM: &str = "axon_admin_authority";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Mapping {
    version: u8,
    source: String,
    claim: String,
    output: String,
    client_id: String,
    audience: String,
    permissions: Vec<String>,
}

fn accepts(raw: &str, client: &str, audience: &str, catalog: &[&str]) -> bool {
    let Ok(mapping) = serde_json::from_str::<Mapping>(raw) else {
        return false;
    };
    mapping.version == 2
        && mapping.source == "signet.is_admin"
        && mapping.claim == RESERVED_CLAIM
        && mapping.output == "access_token"
        && !client.is_empty()
        && !audience.is_empty()
        && mapping.client_id == client
        && mapping.audience == audience
        && !catalog.is_empty()
        && catalog.iter().all(|id| id.starts_with("admin:") && !id.contains('*'))
        && catalog.windows(2).all(|pair| pair[0] < pair[1])
        && mapping.permissions.iter().map(String::as_str).eq(catalog.iter().copied())
}

#[test]
fn accepts_only_the_exact_typed_mapping() {
    let raw = r#"{"version":2,"source":"signet.is_admin","claim":"axon_admin_authority",
        "output":"access_token","client_id":"axon","audience":"https://axon.test/resource",
        "permissions":["admin:standing:inbox","admin:standing:revoke"]}"#;
    let approved = ["admin:standing:inbox", "admin:standing:revoke"];
    let ok = |raw: &str| accepts(raw, "axon", "https://axon.test/resource", &approved);
    assert!(ok(raw));
    for invalid in [
        raw.replace("\"version\":2", "\"version\":2,\"version\":2"),
        raw.replace("\"version\":2", "\"version\":1"),
        raw.replace("\"version\":2", "\"version\":2,\"extra\":true"),
        raw.replace("\"version\":2", "\"version\":2.0"),
        raw.replace("axon_admin_authority", "axon_admin"),
        raw.replace("access_token", "userinfo"),
        raw.replace("axon.test", "other.test"),
        raw.replace("admin:standing:revoke", "admin:standing:inbox"),
        raw.replace("admin:standing:revoke", "admin:standing:*"),
        raw.replace(",\"admin:standing:revoke\"", ""),
    ] {
        assert!(!ok(&invalid), "{invalid}");
    }
}
