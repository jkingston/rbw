use anyhow::{bail, Context as _};
use base64::Engine as _;
use serde_json::{json, Value};
use std::io::{BufRead as _, Write as _};
use zeroize::Zeroizing;

use rbw::{cipherstring::CipherString, locked::Keys};

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
            "status": state, "serverUrl": config.base_url(),
            "userEmail": config.email, "userId": id,
        }),
    )?;
    println!();
    Ok(())
}

fn export_keys(password: &[u8], salt: &str) -> anyhow::Result<Keys> {
    let mut material = Zeroizing::new([0_u8; 32]);
    pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(
        password,
        salt.as_bytes(),
        600_000,
        &mut *material,
    )?;
    let hkdf = hkdf::Hkdf::<sha2::Sha256>::from_prk(&*material)
        .map_err(|_| anyhow::anyhow!("invalid export key"))?;
    let mut bytes = rbw::locked::Vec::new();
    bytes.extend(std::iter::repeat_n(0, 64));
    hkdf.expand(b"enc", &mut bytes.data_mut()[..32])
        .map_err(|_| anyhow::anyhow!("invalid export encryption key"))?;
    hkdf.expand(b"mac", &mut bytes.data_mut()[32..])
        .map_err(|_| anyhow::anyhow!("invalid export authentication key"))?;
    Ok(Keys::new(bytes))
}

fn decrypt_bytes(value: &str, keys: &Keys) -> anyhow::Result<Vec<u8>> {
    Ok(CipherString::new(value)?.decrypt_symmetric(keys, None)?)
}

// Work from raw sync JSON so passkeys and newly added cipher fields survive.
// Decrypt only cipherstrings, never recurse into their decrypted contents.
fn decrypt_tree(value: &mut Value, keys: &Keys) -> anyhow::Result<()> {
    match value {
        Value::String(s) if s.starts_with("2.") && s.contains('|') => {
            let bytes = decrypt_bytes(s, keys)?;
            *s = String::from_utf8(bytes.clone())
                .unwrap_or_else(|_| rbw::base64::encode(bytes));
        }
        Value::Array(values) => {
            for value in values {
                decrypt_tree(value, keys)?;
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                decrypt_tree(value, keys)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn required_str<'a>(
    value: &'a Value,
    field: &str,
) -> anyhow::Result<&'a str> {
    value[field]
        .as_str()
        .with_context(|| format!("sync response missing {field}"))
}

fn vault_payload(
    sync: &Value,
    keys: &Keys,
    org_id: Option<&str>,
) -> anyhow::Result<Value> {
    let mut items = Vec::new();
    for cipher in sync["ciphers"]
        .as_array()
        .context("sync response missing ciphers")?
    {
        if cipher["organizationId"].as_str() != org_id {
            continue;
        }
        let mut item = cipher.clone();
        let item_key = item
            .get("key")
            .and_then(Value::as_str)
            .map(|key| -> anyhow::Result<Keys> {
                Ok(Keys::new(
                    CipherString::new(key)?.decrypt_locked_symmetric(keys)?,
                ))
            })
            .transpose()?;
        item.as_object_mut()
            .context("invalid cipher")?
            .remove("key");
        decrypt_tree(&mut item, item_key.as_ref().unwrap_or(keys))
            .with_context(|| {
                format!("could not decrypt item {}", cipher["id"])
            })?;
        items.push(item);
    }
    let mut folders = if org_id.is_none() {
        sync["folders"]
            .as_array()
            .context("sync response missing folders")?
            .clone()
    } else {
        Vec::new()
    };
    for folder in &mut folders {
        decrypt_tree(folder, keys)?;
    }
    let mut collections = Vec::new();
    if let Some(org_id) = org_id {
        for collection in sync["collections"]
            .as_array()
            .context("sync response missing collections")?
        {
            if collection["organizationId"].as_str() == Some(org_id) {
                let mut collection = collection.clone();
                decrypt_tree(&mut collection, keys)?;
                collections.push(collection);
            }
        }
    }
    Ok(
        json!({ "encrypted": false, "folders": folders, "collections": collections, "items": items }),
    )
}

fn protect(payload: &Value, password: &[u8]) -> anyhow::Result<Value> {
    let salt = uuid::Uuid::new_v4().to_string();
    let keys = export_keys(password, &salt)?;
    let clear = Zeroizing::new(serde_json::to_vec(payload)?);
    Ok(json!({
        "encrypted": true, "passwordProtected": true,
        "salt": salt, "kdfType": 0, "kdfIterations": 600_000,
        "encKeyValidation_DO_NOT_EDIT": CipherString::encrypt_symmetric(&keys, uuid::Uuid::new_v4().to_string().as_bytes())?.to_string(),
        "data": CipherString::encrypt_symmetric(&keys, &clear)?.to_string(),
    }))
}

pub fn export(
    org_id: Option<&str>,
    expected_user_id: Option<&str>,
    expected_server_url: Option<&str>,
) -> anyhow::Result<()> {
    let config = rbw::config::Config::load()?;
    let email = config.email.as_deref().context("run rbw login first")?;
    let mut db = rbw::db::Db::load(&config.server_name(), email)?;
    let user_id = account_id(&db)?;
    if expected_user_id.is_some_and(|id| id != user_id)
        || expected_server_url.is_some_and(|url| url != config.base_url())
    {
        bail!("configured account changed since the backup prompt; retry");
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

    let runtime = tokio::runtime::Runtime::new()?;
    let (token, sync) = runtime.block_on(rbw::actions::sync_raw(
        db.access_token.as_deref().context("run rbw login first")?,
        db.refresh_token.as_deref().context("run rbw login first")?,
    ))?;
    if let Some(token) = token {
        db.access_token = Some(token);
        db.save(&config.server_name(), email)?;
    }
    if required_str(&sync["profile"], "id")? != user_id {
        bail!("account changed during export; retry after rbw login");
    }
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
    let encrypted = protect(&payload, password.as_bytes())?;
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
}
