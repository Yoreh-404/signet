#[test]
fn invitation_public_response_excludes_reveal_material() {
    let invitation = crate::db::InvitationRecord {
        id: "invitation-id".to_string(),
        code_hash: "hash".to_string(),
        code_prefix: "AUTH-abc".to_string(),
        code_reveal_key_id: Some("signing-key-1".to_string()),
        code_reveal_ciphertext: Some("ciphertext".to_string()),
        code_type: "login".to_string(),
        login_code_level: "account_recovery".to_string(),
        allowed_client_ids: "[]".to_string(),
        organization_id: None,
        organization_role: None,
        description: Some("temporary access".to_string()),
        authorized_email: Some("visitor@example.com".to_string()),
        authorized_username: Some("visitor".to_string()),
        authorized_user_id: Some("user-id".to_string()),
        authorized_display_name: Some("Visitor".to_string()),
        expires_at: Some(1000),
        max_uses: Some(1),
        uses_count: 1,
        is_active: 1,
        created_by: Some("admin-id".to_string()),
        created_at: 1,
        updated_at: 2,
    };
    let public = invitation.public().unwrap();
    let serialized = serde_json::to_string(&public).unwrap();

    assert!(public.can_reveal);
    assert!(!serialized.contains("hash"));
    assert!(!serialized.contains("ciphertext"));
    assert!(!serialized.contains("signing-key-1"));
}

#[test]
fn invitation_redemption_update_is_guarded_by_state_and_use_limit() {
    for kind in [
        crate::config::DatabaseKind::Sqlite,
        crate::config::DatabaseKind::Postgres,
        crate::config::DatabaseKind::Mysql,
    ] {
        let sql = super::redeem_invitation_update_sql(kind);
        assert!(sql.contains("is_active = 1"));
        assert!(sql.contains("expires_at IS NULL OR expires_at >="));
        assert!(sql.contains("max_uses IS NULL OR uses_count < max_uses"));
    }
}
