#!/usr/bin/env python3
"""Register a user against a running vaultwarden server.

vaultwarden's own `register` CLI is awkward to drive from a container
(no output, refuses once RSA keys exist), so this implements the same
client-side key derivation the web vault uses:

  master    = PBKDF2-SHA256(password, email, iterations)
  enc|mac   = HKDF-Expand(master, "enc"|"mac")
  key       = random 64 bytes, AES-256-CBC encrypted under enc|mac
  privkey   = RSA PEM with a 32-byte header, encrypted under the user key

Then: prelogin, request a registration token (no SMTP configured, so
the server hands the token back directly), register/finish, and prove
login works with a token exchange.

Run inside a container with `cryptography` installed, e.g.

  docker run -i --rm --network host python:3.12-slim \
      sh -c "pip install -q cryptography && cat > /r.py && python /r.py URL EMAIL PASSWORD" < register.py
"""

import argparse
import base64
import hashlib
import hmac as hmacmod
import json
import secrets
import urllib.error
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

ITERATIONS = 600000


def b64(b):
    return base64.b64encode(b).decode()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("email")
    ap.add_argument("password")
    args = ap.parse_args()

    email = args.email.lower()
    mp = args.password.encode()

    master = hashlib.pbkdf2_hmac(
        "sha256", mp, email.encode(), ITERATIONS, 32
    )
    enc_key = HKDFExpand(
        algorithm=hashes.SHA256(), length=32, info=b"enc"
    ).derive(master)
    mac_key = HKDFExpand(
        algorithm=hashes.SHA256(), length=32, info=b"mac"
    ).derive(master)
    password_hash = b64(
        hashlib.pbkdf2_hmac("sha256", master, mp, 1, 32)
    )

    def enc_sym(key32, mackey32, plaintext):
        iv = secrets.token_bytes(16)
        pad = 16 - (len(plaintext) % 16)
        enc = Cipher(algorithms.AES(key32), modes.CBC(iv)).encryptor()
        ct = enc.update(plaintext + bytes([pad]) * pad) + enc.finalize()
        mac = hmacmod.new(mackey32, iv + ct, hashlib.sha256).digest()
        return f"2.{b64(iv)}|{b64(ct)}|{b64(mac)}"

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = rsa_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = rsa_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # user symmetric key, protected by the stretched master key
    sym_key = secrets.token_bytes(64)
    protected_key = enc_sym(enc_key, mac_key, sym_key)
    # RSA private key: 32-byte header + PEM, encrypted under the user key
    pri_encrypted = enc_sym(
        sym_key[:32], sym_key[32:], secrets.token_bytes(32) + priv_pem
    )
    pub_b64 = b64(pub_pem)

    def req(path, data=None, form=None, token=None, get=False):
        if get:
            r = urllib.request.Request(args.url + path, method="GET")
        elif form is not None:
            r = urllib.request.Request(
                args.url + path,
                data=urllib.parse.urlencode(form).encode(),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        else:
            r = urllib.request.Request(
                args.url + path,
                data=json.dumps(data).encode(),
                headers={"Content-Type": "application/json"},
            )
        if token:
            r.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(r) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            print(f"HTTP {e.code} on {path}: {body[:300]}")
            raise

    req("/identity/accounts/prelogin", {"email": email})

    # registration token: with no SMTP configured the server returns it
    status, raw = req(
        "/identity/accounts/register/send-verification-email",
        {"email": email, "name": "RBW E2E"},
    )
    token_value = None
    if raw.strip():
        try:
            parsed = json.loads(raw.decode())
            if isinstance(parsed, str):
                token_value = parsed
            else:
                token_value = parsed.get("Token") or parsed.get("token")
        except json.JSONDecodeError:
            token_value = raw.decode().strip().strip('"')

    status, _ = req(
        "/identity/accounts/register/finish",
        {
            "email": email,
            "key": protected_key,
            "masterPasswordHash": password_hash,
            "kdf": 0,
            "kdfIterations": ITERATIONS,
            "keys": {
                "publicKey": pub_b64,
                "encryptedPrivateKey": pri_encrypted,
            },
            "masterPasswordHint": "e2e",
            "emailVerificationToken": token_value,
        },
    )
    print(f"register status={status}")

    # prove login works: token exchange with the master password hash
    status, raw = req(
        "/identity/connect/token",
        form={
            "grant_type": "password",
            "username": email,
            "password": password_hash,
            "scope": "api offline_access",
            "client_id": "web",
            "deviceType": 9,
            "deviceIdentifier": secrets.token_hex(16),
            "deviceName": "register-script",
            "devicePushToken": "",
        },
    )
    tok = json.loads(raw)
    print(f"token status={status} has_access_token={'access_token' in tok}")


if __name__ == "__main__":
    main()
