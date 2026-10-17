use crate::{cipherstring::CipherString, locked::Keys};
use anyhow::Context as _;
use serde_json::{json, Value};
use zeroize::Zeroizing;

pub fn export_keys(password: &[u8], salt: &str) -> anyhow::Result<Keys> {
    let mut material = Zeroizing::new([0_u8; 32]);
    pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(
        password,
        salt.as_bytes(),
        600_000,
        &mut *material,
    )?;
    let hkdf = hkdf::Hkdf::<sha2::Sha256>::from_prk(&*material)
        .map_err(|_| anyhow::anyhow!("invalid export key"))?;
    let mut bytes = crate::locked::Vec::new();
    bytes.extend(std::iter::repeat_n(0, 64));
    hkdf.expand(b"enc", &mut bytes.data_mut()[..32])
        .map_err(|_| anyhow::anyhow!("invalid export encryption key"))?;
    hkdf.expand(b"mac", &mut bytes.data_mut()[32..])
        .map_err(|_| anyhow::anyhow!("invalid export authentication key"))?;
    Ok(Keys::new(bytes))
}

pub fn decrypt_bytes(value: &str, keys: &Keys) -> anyhow::Result<Vec<u8>> {
    Ok(CipherString::new(value)?.decrypt_symmetric(keys, None)?)
}

// Work from raw sync JSON so passkeys and newly added cipher fields survive.
// Decrypt only cipherstrings, never recurse into their decrypted contents.
pub fn decrypt_tree(value: &mut Value, keys: &Keys) -> anyhow::Result<()> {
    match value {
        Value::String(s) if s.starts_with("2.") && s.contains('|') => {
            let bytes = decrypt_bytes(s, keys)?;
            *s = String::from_utf8(bytes.clone())
                .unwrap_or_else(|_| crate::base64::encode(bytes));
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

pub fn required_str<'a>(
    value: &'a Value,
    field: &str,
) -> anyhow::Result<&'a str> {
    value[field]
        .as_str()
        .with_context(|| format!("sync response missing {field}"))
}

pub fn vault_payload(
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

pub fn protect(payload: &Value, password: &[u8]) -> anyhow::Result<Value> {
    let salt = uuid::Uuid::new_v4().to_string();
    let keys = export_keys(password, &salt)?;
    protect_with_keys(payload, &salt, &keys)
}

pub fn protect_with_keys(
    payload: &Value,
    salt: &str,
    keys: &Keys,
) -> anyhow::Result<Value> {
    let clear = Zeroizing::new(serde_json::to_vec(payload)?);
    Ok(json!({
        "encrypted": true, "passwordProtected": true,
        "salt": salt, "kdfType": 0, "kdfIterations": 600_000,
        "encKeyValidation_DO_NOT_EDIT": CipherString::encrypt_symmetric(keys, uuid::Uuid::new_v4().to_string().as_bytes())?.to_string(),
        "data": CipherString::encrypt_symmetric(keys, &clear)?.to_string(),
    }))
}
