//! Application-level encryption for secrets which must be recovered at use
//! time.  Passwords and recovery codes remain one-way hashes; TOTP seeds are
//! the deliberate exception because the server must calculate a code.

use crate::{
    config::Settings,
    error::{AppError, AppResult},
};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use rand_core::{OsRng, RngCore};

const TOTP_PREFIX: &str = "signet-totp-secret:v1";
const TOTP_AAD: &[u8] = b"signet:totp-secret:v1";

#[derive(Clone)]
pub struct SecretStore {
    key: [u8; 32],
}

impl SecretStore {
    pub fn from_settings(settings: &Settings) -> AppResult<Self> {
        let value = settings.security.totp_encryption_key.trim();
        if value.is_empty() {
            return Err(AppError::Configuration(
                "security.totp_encryption_key is required before enabling TOTP".to_string(),
            ));
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(value)
            .or_else(|_| STANDARD.decode(value))
            .map_err(|_| {
                AppError::Configuration("security.totp_encryption_key is invalid".to_string())
            })?;
        let key: [u8; 32] = decoded.try_into().map_err(|_| {
            AppError::Configuration(
                "security.totp_encryption_key must decode to exactly 32 bytes".to_string(),
            )
        })?;
        Ok(Self { key })
    }

    pub fn encrypt_totp(&self, plaintext: &str) -> AppResult<String> {
        if plaintext.trim().is_empty() {
            return Err(AppError::BadRequest(
                "TOTP secret cannot be empty".to_string(),
            ));
        }
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|_| AppError::Configuration("TOTP encryption key is invalid".to_string()))?;
        let mut nonce_bytes = [0_u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::try_from(&nonce_bytes[..]).map_err(|_| {
            AppError::Internal("failed to construct TOTP encryption nonce".to_string())
        })?;
        let ciphertext = cipher
            .encrypt(
                &nonce,
                aes_gcm::aead::Payload {
                    msg: plaintext.as_bytes(),
                    aad: TOTP_AAD,
                },
            )
            .map_err(|_| AppError::Internal("failed to encrypt TOTP secret".to_string()))?;
        Ok(format!(
            "{TOTP_PREFIX}.{}.{}",
            URL_SAFE_NO_PAD.encode(nonce_bytes),
            URL_SAFE_NO_PAD.encode(ciphertext)
        ))
    }

    pub fn decrypt_totp(&self, ciphertext: &str) -> AppResult<String> {
        let mut parts = ciphertext.split('.');
        if parts.next() != Some(TOTP_PREFIX) {
            return Err(AppError::Configuration(
                "stored TOTP secret is not encrypted; re-enrollment is required".to_string(),
            ));
        }
        let nonce_bytes: [u8; 12] = URL_SAFE_NO_PAD
            .decode(parts.next().unwrap_or_default())
            .map_err(|_| AppError::Configuration("stored TOTP secret is invalid".to_string()))?
            .try_into()
            .map_err(|_| AppError::Configuration("stored TOTP secret is invalid".to_string()))?;
        let ciphertext = URL_SAFE_NO_PAD
            .decode(parts.next().unwrap_or_default())
            .map_err(|_| AppError::Configuration("stored TOTP secret is invalid".to_string()))?;
        if parts.next().is_some() {
            return Err(AppError::Configuration(
                "stored TOTP secret is invalid".to_string(),
            ));
        }
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|_| AppError::Configuration("TOTP encryption key is invalid".to_string()))?;
        let nonce = Nonce::try_from(&nonce_bytes[..])
            .map_err(|_| AppError::Configuration("stored TOTP secret is invalid".to_string()))?;
        let plaintext = cipher
            .decrypt(
                &nonce,
                aes_gcm::aead::Payload {
                    msg: &ciphertext,
                    aad: TOTP_AAD,
                },
            )
            .map_err(|_| AppError::Configuration("stored TOTP secret is invalid".to_string()))?;
        String::from_utf8(plaintext)
            .map_err(|_| AppError::Configuration("stored TOTP secret is invalid".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings_with_key() -> Settings {
        let mut settings: Settings =
            toml::from_str(include_str!("../../config/default.toml")).unwrap();
        settings.security.totp_encryption_key = URL_SAFE_NO_PAD.encode([7_u8; 32]);
        settings
    }

    #[test]
    fn totp_secret_is_authenticated_and_not_plaintext() {
        let store = SecretStore::from_settings(&settings_with_key()).unwrap();
        let ciphertext = store.encrypt_totp("JBSWY3DPEHPK3PXP").unwrap();
        assert!(!ciphertext.contains("JBSWY3DPEHPK3PXP"));
        assert_eq!(store.decrypt_totp(&ciphertext).unwrap(), "JBSWY3DPEHPK3PXP");
        let tampered = format!("{ciphertext}x");
        assert!(store.decrypt_totp(&tampered).is_err());
    }
}
