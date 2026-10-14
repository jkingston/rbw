#!/usr/bin/env bash
# End-to-end test of rbw against a throwaway vaultwarden server.
#
# Everything runs in containers: vaultwarden with a fresh volume, plus a
# minimal harness image (rust + curl/jq/ssh/python3-cryptography) that
# builds rbw from this checkout and runs the assertions (e2e.sh). The
# cargo registry and target dir live on named volumes so reruns are fast.
#
# Requires: docker.
#
# Usage: tests/vaultwarden/run.sh
#
# vaultwarden is pinned to 1.36.x: older releases drop the ssh key
# payload on sync (the sshKey field comes back null). Newer releases
# (1.37+) additionally require an encryptedFor field on cipher writes;
# rbw now sends it, and the suite is green against 1.37.4 as well.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VW_IMAGE="${VW_IMAGE:-vaultwarden/server:1.36.0}"
NET="rbw-e2e-$$"
VW="rbw-e2e-vw-$$"
VW_DATA="$VW-data"

cleanup() {
    docker rm -f "$VW" &>/dev/null || true
    docker volume rm "$VW_DATA" &>/dev/null || true
    docker network rm "$NET" &>/dev/null || true
}
trap cleanup EXIT

echo "=== starting vaultwarden ($VW_IMAGE) ==="
docker network create "$NET" >/dev/null || exit 1
docker run -d --name "$VW" --network "$NET" \
    -e SIGNUPS_ALLOWED=true \
    -v "$VW_DATA:/data" --tmpfs /tmp \
    "$VW_IMAGE" >/dev/null || exit 1

echo "=== building harness image ==="
HARNESS="rbw-e2e-harness:$$"
docker build -q -t "$HARNESS" \
    -f "$REPO/tests/vaultwarden/Dockerfile" "$REPO/tests/vaultwarden" \
    >/dev/null || exit 1

# custom bridge networks NAT to the internet, so cargo downloads work
# from the same network that resolves the vaultwarden container name.
echo "=== running e2e suite ==="
docker run -i --rm --network "$NET" \
    -e VW_URL="http://$VW" \
    -v "$REPO:/src:ro" \
    -v rbw-e2e-cargo:/cache/cargo \
    -v rbw-e2e-target:/cache/target \
    "$HARNESS" \
    bash /src/tests/vaultwarden/e2e.sh
rc=$?

docker rm -f "$VW" >/dev/null 2>&1 || true
docker volume rm "$VW_DATA" >/dev/null 2>&1 || true
docker network rm "$NET" >/dev/null 2>&1 || true
docker rmi "$HARNESS" >/dev/null 2>&1 || true
exit "$rc"
