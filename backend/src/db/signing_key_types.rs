use diesel::sql_types::{BigInt, Integer, Nullable, Text};

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct SigningKeyRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub kid: String,
    #[diesel(sql_type = Text)]
    pub private_key_pem: String,
    #[diesel(sql_type = Integer)]
    pub is_active: i32,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub activated_at: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub retired_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct NewSigningKey {
    pub kid: String,
    pub private_key_pem: String,
    pub is_active: bool,
}
