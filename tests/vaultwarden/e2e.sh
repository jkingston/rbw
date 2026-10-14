#!/usr/bin/env bash
# Runs inside the harness container (see run.sh): builds rbw from the
# mounted repo, registers an account against vaultwarden, and exercises
# the client. Communicates only over the shared docker network.
#
# Fork-only features (ssh-key create/edit, the encode/create-raw/edit-raw
# escape hatch) are detected from the CLI and skipped when absent, so
# this passes on plain upstream too — the fork branch runs the full set.
set -uo pipefail

SRC="${SRC:-/src}"
VW_URL="${VW_URL:-http://vw}"
EMAIL=vault-test@example.com
MASTER='correct horse battery staple'

export CARGO_HOME="${CARGO_HOME:-/cache/cargo}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/cache/target}"
RBW_BIN="$CARGO_TARGET_DIR/debug/rbw"
# the client spawns rbw-agent from PATH
export PATH="$CARGO_TARGET_DIR/debug:$PATH"

pass=0
fail=0
ok() { echo "  PASS: $1"; pass=$((pass + 1)); }
bad() {
    echo "  FAIL: $1${2:+ ($2)}"
    fail=$((fail + 1))
}

echo "=== waiting for vaultwarden ==="
for _ in $(seq 1 60); do
    curl -sf "$VW_URL/alive" >/dev/null 2>&1 && break
    sleep 1
done
curl -sf "$VW_URL/alive" >/dev/null 2>&1 || {
    echo "vaultwarden never came up at $VW_URL"
    exit 1
}

echo "=== building rbw ==="
(cd "$SRC" && cargo build) || exit 1
[[ -x "$RBW_BIN" ]] || exit 1

WORK=$(mktemp -d)
export HOME="$WORK/home"
export XDG_CONFIG_HOME="$HOME/.config"
export XDG_CACHE_HOME="$HOME/.cache"
export XDG_RUNTIME_DIR="$WORK/run"
mkdir -p "$HOME" "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME" "$XDG_RUNTIME_DIR"
chmod 700 "$XDG_RUNTIME_DIR"

echo "=== creating account ==="
python3 "$SRC/tests/vaultwarden/register.py" "$VW_URL" "$EMAIL" "$MASTER" |
    sed 's/^/  /'

# scripted pinentry: answers GETPIN with the master password, and logs
# every prompt so tests can tell whether the agent asked for a password
cat >"$WORK/pinentry-scripted" <<EOF
#!/usr/bin/env bash
printf 'OK Pleased to meet you\n'
while IFS= read -r line; do
    case "\$line" in
        GETPIN*)
            printf '%s\n' "\$line" >> '$WORK/pinentry.log'
            printf 'D %s\nOK\n' '$MASTER'
            ;;
        *) printf 'OK\n' ;;
    esac
done
EOF
chmod 700 "$WORK/pinentry-scripted"

"$RBW_BIN" config set base_url "$VW_URL"
"$RBW_BIN" config set email "$EMAIL"
"$RBW_BIN" config set pinentry "$WORK/pinentry-scripted"

if "$RBW_BIN" sync >/dev/null 2>&1; then
    ok "login + sync against vaultwarden"
else
    bad "login + sync against vaultwarden"
    "$RBW_BIN" sync 2>&1 | sed 's/^/    /' | head -10
    exit 1
fi

echo "=== forced re-login with a live session ==="
# rbw login must re-authenticate (prompt for the password) even when the
# db already holds tokens; it used to be a silent no-op
: >"$WORK/pinentry.log"
if "$RBW_BIN" login >/dev/null 2>&1 && [[ -s "$WORK/pinentry.log" ]]; then
    ok "rbw login re-authenticates instead of no-op ack"
else
    bad "rbw login re-authenticates instead of no-op ack"
fi
"$RBW_BIN" sync >/dev/null 2>&1 &&
    ok "sync works after forced login" || bad "sync works after forced login"

echo "=== login item create/edit (line 1 = password, rest = notes) ==="
if printf 'pw-one\n\nnote-body\n' |
    "$RBW_BIN" add e2e/note >/dev/null 2>&1; then
    ok "rbw add from piped stdin"
else
    bad "rbw add from piped stdin"
fi
[[ "$("$RBW_BIN" get e2e/note 2>/dev/null)" == "pw-one" ]] &&
    ok "password round-trips" || bad "password round-trips" "got [$("$RBW_BIN" get e2e/note 2>&1)]"
[[ "$("$RBW_BIN" get --field=notes e2e/note 2>/dev/null)" == "note-body" ]] &&
    ok "notes round-trip" || bad "notes round-trip"
printf 'pw-two\n' | "$RBW_BIN" edit e2e/note >/dev/null 2>&1 || true
[[ "$("$RBW_BIN" get e2e/note 2>/dev/null)" == "pw-two" ]] &&
    ok "password update in place" || bad "password update in place"

HAS_SSH=0
"$RBW_BIN" add --help 2>&1 | grep -q -- '--private-key' && HAS_SSH=1
HAS_RAW=0
"$RBW_BIN" encode --help >/dev/null 2>&1 && HAS_RAW=1

if [[ "$HAS_SSH" == 1 ]]; then
    echo "=== ssh key item create/read ==="
    ssh-keygen -t ed25519 -N "" -C "e2e-initial" -f "$WORK/k1" -q
    P1=$(cat "$WORK/k1")
    U1=$(cat "$WORK/k1.pub")
    if "$RBW_BIN" add e2e/ssh --private-key <(printf '%s\n' "$P1") \
        --public-key <(printf '%s\n' "$U1") </dev/null >/dev/null 2>&1; then
        ok "rbw add --private-key/--public-key"
    else
        bad "rbw add --private-key/--public-key"
    fi
    [[ "$("$RBW_BIN" get --field=private_key e2e/ssh 2>/dev/null)" == "$P1" ]] &&
        ok "private key round-trips" || bad "private key round-trips"
    [[ "$("$RBW_BIN" get --field=public_key e2e/ssh 2>/dev/null)" == "$U1" ]] &&
        ok "public key round-trips" || bad "public key round-trips"
    [[ -n "$("$RBW_BIN" get --field=fingerprint e2e/ssh 2>/dev/null)" ]] &&
        ok "fingerprint derived" || bad "fingerprint derived"

    echo "=== ssh key item edit ==="
    ssh-keygen -t ed25519 -N "" -C "e2e-rotated" -f "$WORK/k2" -q
    P2=$(cat "$WORK/k2")
    U2=$(cat "$WORK/k2.pub")
    if "$RBW_BIN" edit e2e/ssh --private-key <(printf '%s\n' "$P2") \
        --public-key <(printf '%s\n' "$U2") </dev/null >/dev/null 2>&1; then
        ok "rbw edit --private-key/--public-key"
    else
        bad "rbw edit --private-key/--public-key"
    fi
    [[ "$("$RBW_BIN" get --field=public_key e2e/ssh 2>/dev/null)" == "$U2" ]] &&
        ok "rotated public key round-trips" || bad "rotated public key round-trips"
    got_f=$("$RBW_BIN" get --field=fingerprint e2e/ssh 2>/dev/null)
    exp_f=$(printf '%s\n' "$U2" | ssh-keygen -lf - | awk '{print $2}')
    [[ "$got_f" == "$exp_f" ]] &&
        ok "fingerprint recomputed on rotate" || bad "fingerprint recomputed" "got [$got_f] want [$exp_f]"
else
    echo "=== ssh key items: skipped (no --private-key support) ==="
fi

if [[ "$HAS_RAW" == 1 ]]; then
    echo "=== encode + create-raw + edit-raw ==="
    jq -n --arg name "e2e/rawlogin" \
        '{type: 1, name: $name, login: {username: "user2", password: "pw1"},
          fields: [{type: 1, name: "label", value: "secret1"}]}' |
        "$RBW_BIN" encode >"$WORK/body.json" 2>"$WORK/enc.err"
    [[ -s "$WORK/body.json" ]] &&
        ok "rbw encode produces a body" || bad "rbw encode" "$(head -1 "$WORK/enc.err")"
    jq -e '.fields[0].name | startswith("2.")' "$WORK/body.json" >/dev/null &&
        ok "encode encrypts field names" || bad "encode encrypts field names"
    jq -e '.login.password | startswith("2.")' "$WORK/body.json" >/dev/null &&
        ok "encode encrypts login values" || bad "encode encrypts login values"
    if "$RBW_BIN" create-raw <"$WORK/body.json" >/dev/null 2>&1; then
        ok "rbw create-raw"
    else
        bad "rbw create-raw"
    fi
    [[ "$("$RBW_BIN" get e2e/rawlogin 2>/dev/null)" == "pw1" ]] &&
        ok "create-raw login readable" || bad "create-raw login readable"
    [[ "$("$RBW_BIN" get --field=label e2e/rawlogin 2>/dev/null)" == "secret1" ]] &&
        ok "create-raw custom field readable" || bad "create-raw custom field readable"
    jq -n --arg name "e2e/rawlogin" \
        '{type: 1, name: $name, login: {username: "user3", password: "pw2"}}' |
        "$RBW_BIN" encode 2>/dev/null |
        "$RBW_BIN" edit-raw e2e/rawlogin >/dev/null 2>&1 &&
        ok "rbw edit-raw" || bad "rbw edit-raw"
    [[ "$("$RBW_BIN" get e2e/rawlogin 2>/dev/null)" == "pw2" ]] &&
        ok "edit-raw replaced password" || bad "edit-raw replaced password"
else
    echo "=== encode/create-raw/edit-raw: skipped (commands absent) ==="
fi

echo "=== expired session recovery ==="
# simulate an expired session the way the server leaves it: tokens present
# in the db file but rejected on use. rbw sync must explain the failure
# instead of leaking a serde error, and rbw login must be able to recover.
"$RBW_BIN" stop-agent
DB="$(find "$XDG_CACHE_HOME/rbw" -maxdepth 1 -name '*.json' -print -quit)"
if [[ -f "$DB" ]] &&
    jq '.access_token = "expired" | .refresh_token = "expired"' \
        "$DB" >"$DB.tmp" && mv "$DB.tmp" "$DB"; then
    out="$("$RBW_BIN" sync 2>&1)"
    if [[ "$out" == *"rbw login"* && "$out" != *"missing field"* ]]; then
        ok "sync with rejected tokens points at rbw login"
    else
        bad "sync with rejected tokens points at rbw login" "$out"
    fi
    : >"$WORK/pinentry.log"
    if "$RBW_BIN" login >/dev/null 2>&1 && [[ -s "$WORK/pinentry.log" ]]; then
        ok "rbw login recovers from a rejected refresh token"
    else
        bad "rbw login recovers from a rejected refresh token"
    fi
    "$RBW_BIN" sync >/dev/null 2>&1 &&
        ok "sync works after re-login" || bad "sync works after re-login"
else
    bad "find rbw cache db to expire" "no db json under $XDG_CACHE_HOME/rbw"
fi

echo "=== list/search ==="
"$RBW_BIN" list 2>/dev/null | grep -q "e2e/note" &&
    ok "rbw list includes new item" || bad "rbw list includes new item"

echo ""
echo "Passed: $pass  Failed: $fail"
exit "$fail"
