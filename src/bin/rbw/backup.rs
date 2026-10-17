use anyhow::{bail, Context as _};
use base64::Engine as _;
use serde_json::{json, Value};
use std::io::{BufRead as _, Write as _};
use zeroize::Zeroizing;

use rbw::{cipherstring::CipherString, locked::Keys};

fn server_url(config: &rbw::config::Config) -> String {
    config
        .base_url
        .as_deref()
        .unwrap_or("https://bitwarden.com")
        .trim_end_matches('/')
        .to_string()
}

fn account_id(db: &rbw::db::Db) -> anyhow::Result<String> {
    let token = db.access_token.as_deref().context("run rbw login first")?;
    let payload = token.split('.').nth(1).context("invalid access token")?;
    let payload =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload)?;
    let claims: Value = serde_json::from_slice(&payload)?;
    Ok(claims["sub"]
        .as_str()
        .context("missing account id")?
        .to_string())
}

pub fn status() -> anyhow::Result<()> {
    let config = rbw::config::Config::load()?;
    let db = config.email.as_ref().and_then(|email| {
        rbw::db::Db::load(&config.server_name(), email).ok()
    });
    let id = db.as_ref().and_then(|db| account_id(db).ok());
    let logged_in = id.is_some()
        && db.as_ref().is_some_and(|db| db.refresh_token.is_some());
    let state = if !logged_in {
        "unauthenticated"
    } else if crate::actions::unlocked().is_ok() {
        "unlocked"
    } else {
        "locked"
    };
    serde_json::to_writer(
        std::io::stdout(),
        &json!({
        "status": state, "serverUrl": server_url(&config),
            "userEmail": config.email, "userId": id,
        }),
    )?;
    println!();
    Ok(())
}

use rbw::backup::*;

#[derive(Debug, thiserror::Error)]
#[error("backup key cache unavailable: {0}")]
pub struct CacheUnavailable(pub String);

fn cache_unavailable(error: impl std::fmt::Display) -> anyhow::Error {
    CacheUnavailable(error.to_string()).into()
}

fn fresh_sync(
    config: &rbw::config::Config,
    db: &mut rbw::db::Db,
) -> anyhow::Result<Value> {
    let runtime = tokio::runtime::Runtime::new()?;
    let (token, sync) = runtime.block_on(rbw::actions::sync_raw(
        db.access_token.as_deref().context("run rbw login first")?,
        db.refresh_token.as_deref().context("run rbw login first")?,
    ))?;
    if let Some(token) = token {
        db.access_token = Some(token);
        db.save(
            &config.server_name(),
            config.email.as_deref().context("missing email")?,
        )?;
    }
    if required_str(&sync["profile"], "id")? != account_id(db)? {
        bail!("account changed during export; retry after rbw login");
    }
    Ok(sync)
}

fn cached_export(
    config: &rbw::config::Config,
    db: &mut rbw::db::Db,
    org_id: Option<&str>,
) -> anyhow::Result<()> {
    crate::actions::unlocked().map_err(cache_unavailable)?;
    let server = server_url(config);
    let user_id = account_id(db)?;
    let record = rbw::backup_cache::load(&server, &user_id)
        .map_err(cache_unavailable)?;
    let sync = fresh_sync(config, db)?;
    record
        .validate(&server, &user_id, required_str(&sync["profile"], "key")?)
        .map_err(cache_unavailable)?;
    let encrypted = crate::actions::backup_export(
        sync,
        serde_json::to_value(&record)?,
        org_id,
    )?;
    serde_json::to_writer(std::io::stdout(), &encrypted)?;
    println!();
    Ok(())
}

pub fn verify_export(
    file: &std::path::Path,
    verifier: &std::path::Path,
) -> anyhow::Result<()> {
    crate::actions::unlocked().map_err(cache_unavailable)?;
    let config = rbw::config::Config::load()?;
    let email = config.email.as_deref().context("run rbw login first")?;
    let db = rbw::db::Db::load(&config.server_name(), email)?;
    let user_id = account_id(&db)?;
    let record = rbw::backup_cache::load(&server_url(&config), &user_id)
        .map_err(cache_unavailable)?;
    record.validate_identity(&server_url(&config), &user_id)?;
    let input =
        Zeroizing::new(serde_json::to_vec(&record.verifier_input()?)?);
    let mut child = std::process::Command::new("node")
        .arg(verifier)
        .arg("--key-json")
        .arg(file)
        .stdin(std::process::Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .context("missing verifier stdin")?
        .write_all(&input)?;
    if !child.wait()?.success() {
        bail!("independent backup verification failed");
    }
    Ok(())
}

pub fn export(
    org_id: Option<&str>,
    expected_user_id: Option<&str>,
    expected_server_url: Option<&str>,
    keychain: bool,
    cache_key: bool,
) -> anyhow::Result<()> {
    let config = rbw::config::Config::load()?;
    let email = config.email.as_deref().context("run rbw login first")?;
    let mut db = rbw::db::Db::load(&config.server_name(), email)?;
    let user_id = account_id(&db)?;
    if expected_user_id.is_some_and(|id| id != user_id)
        || expected_server_url.is_some_and(|url| url != server_url(&config))
    {
        bail!("configured account changed since the backup prompt; retry");
    }
    if keychain {
        return cached_export(&config, &mut db, org_id);
    }
    let mut password = Zeroizing::new(String::new());
    std::io::stdin().lock().read_line(&mut password)?;
    if password.ends_with('\n') {
        password.pop();
        if password.ends_with('\r') {
            password.pop();
        }
    }
    if password.is_empty() {
        bail!("empty master password");
    }
    let mut locked_password = rbw::locked::Vec::new();
    locked_password.extend(password.as_bytes().iter().copied());
    let identity = rbw::identity::Identity::new(
        email,
        &rbw::locked::Password::new(locked_password),
        db.kdf.context("missing account KDF")?,
        db.iterations.context("missing account KDF iterations")?,
        db.memory,
        db.parallelism,
    )?;
    // Authenticate the supplied password locally, even if the SSH agent is unlocked.
    CipherString::new(
        db.protected_key.as_deref().context("missing vault key")?,
    )?
    .decrypt_locked_symmetric(&identity.keys)
    .context("master password is incorrect")?;

    let sync = fresh_sync(&config, &mut db)?;
    let personal_keys = Keys::new(
        CipherString::new(required_str(&sync["profile"], "key")?)?
            .decrypt_locked_symmetric(&identity.keys)?,
    );
    let org_keys = if let Some(org_id) = org_id {
        let org = sync["profile"]["organizations"]
            .as_array()
            .context("missing organizations")?
            .iter()
            .find(|org| org["id"].as_str() == Some(org_id))
            .context("organization is not accessible")?;
        let private_key = rbw::locked::PrivateKey::new(
            CipherString::new(required_str(&sync["profile"], "privateKey")?)?
                .decrypt_locked_symmetric(&personal_keys)?,
        );
        Some(Keys::new(
            CipherString::new(required_str(org, "key")?)?
                .decrypt_locked_asymmetric(&private_key)?,
        ))
    } else {
        None
    };
    let payload = vault_payload(
        &sync,
        org_keys.as_ref().unwrap_or(&personal_keys),
        org_id,
    )?;
    let encrypted = if cache_key {
        let record = rbw::backup_cache::CachedKey::new(
            password.as_bytes(),
            &server_url(&config),
            &user_id,
            required_str(&sync["profile"], "key")?,
            &personal_keys,
        )?;
        let encrypted =
            protect_with_keys(&payload, &record.salt, &record.keys()?)?;
        rbw::backup_cache::save(&record)?;
        encrypted
    } else {
        protect(&payload, password.as_bytes())?
    };
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, &encrypted)?;
    writeln!(output)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> Keys {
        let mut bytes = rbw::locked::Vec::new();
        bytes.extend(std::iter::repeat_n(42, 64));
        Keys::new(bytes)
    }

    #[test]
    fn preserves_passkeys_metadata_and_folders() {
        let keys = keys();
        let enc = |s: &str| {
            CipherString::encrypt_symmetric(&keys, s.as_bytes())
                .unwrap()
                .to_string()
        };
        let sync = json!({
            "ciphers": [
                {"id":"personal", "organizationId":null, "name":enc("example"), "favorite":true,
                 "type":1, "login":{"password":enc("pw"), "fido2Credentials":[{"keyValue":enc("passkey"), "counter":"0"}]},
                 "unknownFutureField":{"value":enc("future")}},
                {"id":"org", "organizationId":"org", "name":enc("org")}
            ],
            "folders":[{"id":"empty-folder", "name":enc("empty")}]
        });
        let payload = vault_payload(&sync, &keys, None).unwrap();
        assert_eq!(payload["items"].as_array().unwrap().len(), 1);
        assert_eq!(
            payload["items"][0]["login"]["fido2Credentials"][0]["keyValue"],
            "passkey"
        );
        assert_eq!(
            payload["items"][0]["unknownFutureField"]["value"],
            "future"
        );
        assert_eq!(payload["folders"][0]["name"], "empty");
        assert_eq!(payload["items"][0]["favorite"], true);
    }

    #[test]
    fn encrypted_export_roundtrip_and_wrong_password() {
        let payload = json!({"items":[{"type":5,"sshKey":{"privateKey":"secret"}}], "folders":[]});
        let encrypted = protect(&payload, b"test password").unwrap();
        let keys = export_keys(
            b"test password",
            encrypted["salt"].as_str().unwrap(),
        )
        .unwrap();
        let clear = decrypt_bytes(encrypted["data"].as_str().unwrap(), &keys)
            .unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&clear).unwrap(), payload);
        let wrong = export_keys(
            b"wrong password",
            encrypted["salt"].as_str().unwrap(),
        )
        .unwrap();
        assert!(decrypt_bytes(encrypted["data"].as_str().unwrap(), &wrong)
            .is_err());
    }

    #[test]
    fn corrupted_cipher_aborts_export() {
        let mut value = json!({"name":"2.invalid|invalid|invalid"});
        assert!(decrypt_tree(&mut value, &keys()).is_err());
    }

    #[test]
    fn independent_node_verifier() {
        let Ok(helper) = std::env::var("RBW_EXPORT_VERIFY_HELPER") else {
            return;
        };
        let payload = json!({"items":[{"type":5,"sshKey":{"privateKey":"secret"}}],"folders":[]});
        let encrypted = protect(&payload, b"fixture password").unwrap();
        let mut file = tempfile::NamedTempFile::new().unwrap();
        serde_json::to_writer(&mut file, &encrypted).unwrap();
        for (password, expected) in
            [("fixture password\n", true), ("incorrect\n", false)]
        {
            let mut child = std::process::Command::new("node")
                .arg(&helper)
                .arg("--json")
                .arg(file.path())
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(password.as_bytes())
                .unwrap();
            let output = child.wait_with_output().unwrap();
            assert_eq!(
                output.status.success(),
                expected,
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            if expected {
                let summary: Value =
                    serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(summary["sshKeys"], 1);
                assert_eq!(summary["decryptable"], true);
            }
        }
    }

    #[test]
    fn independent_cached_key_verifier_and_master_recovery() {
        let Ok(helper) = std::env::var("RBW_EXPORT_VERIFY_HELPER") else {
            return;
        };
        let record = rbw::backup_cache::CachedKey::new(
            b"fixture master",
            "server",
            "user",
            "protected",
            &keys(),
        )
        .unwrap();
        let payload = json!({"items":[{"type":5,"sshKey":{"privateKey":"secret"}}],"folders":[]});
        let encrypted = protect_with_keys(
            &payload,
            &record.salt,
            &record.keys().unwrap(),
        )
        .unwrap();
        let mut file = tempfile::NamedTempFile::new().unwrap();
        serde_json::to_writer(&mut file, &encrypted).unwrap();
        let good = record.verifier_input().unwrap();
        let mut wrong_salt = good.clone();
        wrong_salt["salt"] = json!("wrong");
        let mut wrong_key = good.clone();
        wrong_key["encryptionKey"] = json!(rbw::base64::encode([0_u8; 32]));
        for (input, mode, expected) in [
            (serde_json::to_vec(&good).unwrap(), "--key-json", true),
            (
                serde_json::to_vec(&wrong_salt).unwrap(),
                "--key-json",
                false,
            ),
            (serde_json::to_vec(&wrong_key).unwrap(), "--key-json", false),
            (b"fixture master\n".to_vec(), "--json", true),
        ] {
            let mut child = std::process::Command::new("node")
                .arg(&helper)
                .arg(mode)
                .arg(file.path())
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            child.stdin.take().unwrap().write_all(&input).unwrap();
            let output = child.wait_with_output().unwrap();
            assert_eq!(
                output.status.success(),
                expected,
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}
