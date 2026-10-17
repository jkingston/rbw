use crate::{backup, cipherstring::CipherString, locked::Keys};
use anyhow::{bail, Context as _};
use hmac::Mac as _;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroize as _;

/// A dedicated export key, never the master password or vault encryption key.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct CachedKey {
    pub version: u32,
    pub server: String,
    pub user_id: String,
    pub protected_key_hash: String,
    pub salt: String,
    pub validation: String,
    pub authorization: String,
    key: Vec<u8>,
}

impl Drop for CachedKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

pub fn account(server: &str, user_id: &str) -> String {
    let bytes = serde_json::to_vec(&(server, user_id))
        .expect("serializable identity");
    format!("{:x}", Sha256::digest(bytes))
}

pub fn protected_key_hash(protected_key: &str) -> String {
    format!("{:x}", Sha256::digest(protected_key.as_bytes()))
}

impl CachedKey {
    pub fn new(
        password: &[u8],
        server: &str,
        user_id: &str,
        protected_key: &str,
        vault_keys: &Keys,
    ) -> anyhow::Result<Self> {
        let salt = uuid::Uuid::new_v4().to_string();
        let keys = backup::export_keys(password, &salt)?;
        let mut key = keys.enc_key().to_vec();
        key.extend_from_slice(keys.mac_key());
        let mut record = Self {
            version: 1,
            server: server.to_string(),
            user_id: user_id.to_string(),
            protected_key_hash: protected_key_hash(protected_key),
            salt,
            validation: String::new(),
            authorization: String::new(),
            key,
        };
        record.validation = CipherString::encrypt_symmetric(
            &keys,
            &serde_json::to_vec(&record.proof())?,
        )?
        .to_string();
        record.authorization = crate::base64::encode(
            record
                .authorization_mac(vault_keys)?
                .finalize()
                .into_bytes(),
        );
        Ok(record)
    }

    fn authorization_mac(
        &self,
        vault_keys: &Keys,
    ) -> anyhow::Result<hmac::Hmac<sha2::Sha256>> {
        let mut mac =
            hmac::Hmac::<sha2::Sha256>::new_from_slice(vault_keys.mac_key())?;
        // Domain separation prevents using the agent's ordinary encryption API
        // as an oracle to forge permission for an attacker-chosen export key.
        mac.update(b"rbw.backup-cache.authorization.v1\0");
        let bytes = zeroize::Zeroizing::new(serde_json::to_vec(&(
            self.proof(),
            &self.key,
        ))?);
        mac.update(&bytes);
        Ok(mac)
    }

    pub fn authorize(&self, vault_keys: &Keys) -> anyhow::Result<()> {
        self.authorization_mac(vault_keys)?.verify_slice(&crate::base64::decode(&self.authorization)?)
            .map_err(|_| anyhow::anyhow!("backup key was not enrolled with this vault's master password"))
    }

    fn proof(&self) -> Value {
        json!({"version":self.version,"server":self.server,"userId":self.user_id,
            "protectedKeyHash":self.protected_key_hash,"salt":self.salt})
    }

    pub fn keys(&self) -> anyhow::Result<Keys> {
        if self.key.len() != 64 {
            bail!("invalid cached export key length");
        }
        let mut bytes = crate::locked::Vec::new();
        bytes.extend(self.key.iter().copied());
        Ok(Keys::new(bytes))
    }

    pub fn validate(
        &self,
        server: &str,
        user_id: &str,
        protected_key: &str,
    ) -> anyhow::Result<()> {
        if self.protected_key_hash != protected_key_hash(protected_key) {
            bail!("backup key cache is stale or belongs to another account");
        }
        self.validate_identity(server, user_id)
    }

    pub fn validate_identity(
        &self,
        server: &str,
        user_id: &str,
    ) -> anyhow::Result<()> {
        if self.version != 1
            || self.server != server
            || self.user_id != user_id
        {
            bail!("backup key cache belongs to another account");
        }
        let clear = backup::decrypt_bytes(&self.validation, &self.keys()?)?;
        let proof: Value = serde_json::from_slice(&clear)?;
        if proof != self.proof() {
            bail!("backup key cache metadata was modified");
        }
        Ok(())
    }

    pub fn verifier_input(&self) -> anyhow::Result<Value> {
        let keys = self.keys()?;
        Ok(json!({"salt":self.salt,"kdfType":0,"kdfIterations":600_000,
            "encryptionKey":crate::base64::encode(keys.enc_key()),
            "authenticationKey":crate::base64::encode(keys.mac_key())}))
    }
}

const SERVICE: &str = "local.rbw.backup-export-key.v1";

#[cfg(target_os = "macos")]
pub fn load(server: &str, user_id: &str) -> anyhow::Result<CachedKey> {
    // Fail instead of showing a Keychain dialog in an unattended run.
    let _no_ui = security_framework::os::macos::keychain::SecKeychain::disable_user_interaction()?;
    let mut options =
        security_framework::passwords::PasswordOptions::new_generic_password(
            SERVICE,
            &account(server, user_id),
        );
    options.set_access_synchronized(Some(false));
    let bytes = zeroize::Zeroizing::new(
        security_framework::passwords::generic_password(options)?,
    );
    serde_json::from_slice(&bytes).context("invalid backup key cache")
}

#[cfg(target_os = "macos")]
pub fn save(record: &CachedKey) -> anyhow::Result<()> {
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(record)?);
    let mut options =
        security_framework::passwords::PasswordOptions::new_generic_password(
            SERVICE,
            &account(&record.server, &record.user_id),
        );
    options.set_access_synchronized(Some(false));
    options.set_label("rbw backup encryption key");
    options.set_comment("Dedicated export key. Master password and vault keys are not stored here.");
    security_framework::passwords::set_generic_password_options(
        &bytes, options,
    )
    .context("could not store backup key in macOS Keychain")
}

#[cfg(not(target_os = "macos"))]
pub fn load(_: &str, _: &str) -> anyhow::Result<CachedKey> {
    bail!("backup key caching requires macOS Keychain");
}

#[cfg(not(target_os = "macos"))]
pub fn save(_: &CachedKey) -> anyhow::Result<()> {
    bail!("backup key caching requires macOS Keychain");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault_keys() -> Keys {
        let mut bytes = crate::locked::Vec::new();
        bytes.extend(std::iter::repeat_n(42, 64));
        Keys::new(bytes)
    }

    #[test]
    fn cache_is_bound_to_account_and_password_wrapper() {
        let mut record = CachedKey::new(
            b"master",
            "https://example.test",
            "account-a",
            "protected-key-a",
            &vault_keys(),
        )
        .unwrap();
        record
            .validate("https://example.test", "account-a", "protected-key-a")
            .unwrap();
        assert!(record
            .validate(
                "https://elsewhere.test",
                "account-a",
                "protected-key-a"
            )
            .is_err());
        assert!(record
            .validate("https://example.test", "account-b", "protected-key-a")
            .is_err());
        assert!(record
            .validate(
                "https://example.test",
                "account-a",
                "protected-key-after-password-change"
            )
            .is_err());
        record.salt.push('x');
        assert!(record
            .validate("https://example.test", "account-a", "protected-key-a")
            .is_err());
    }

    #[test]
    fn cached_exports_still_decrypt_with_master_password() {
        let record = CachedKey::new(
            b"master",
            "server",
            "user",
            "protected",
            &vault_keys(),
        )
        .unwrap();
        let payload =
            json!({"items":[{"type":2,"notes":"note"}],"folders":[]});
        let first = backup::protect_with_keys(
            &payload,
            &record.salt,
            &record.keys().unwrap(),
        )
        .unwrap();
        let second = backup::protect_with_keys(
            &payload,
            &record.salt,
            &record.keys().unwrap(),
        )
        .unwrap();
        assert_ne!(first["data"], second["data"]);
        let master_keys =
            backup::export_keys(b"master", &record.salt).unwrap();
        let clear = backup::decrypt_bytes(
            second["data"].as_str().unwrap(),
            &master_keys,
        )
        .unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&clear).unwrap(), payload);
    }

    #[test]
    fn agent_rejects_forged_export_keys() {
        let mut record = CachedKey::new(
            b"master",
            "server",
            "user",
            "protected",
            &vault_keys(),
        )
        .unwrap();
        record.authorize(&vault_keys()).unwrap();
        record.key[0] ^= 1;
        assert!(record.authorize(&vault_keys()).is_err());
        record.key[0] ^= 1;
        record.salt.push('x');
        assert!(record.authorize(&vault_keys()).is_err());
    }
}
