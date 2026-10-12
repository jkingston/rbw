# Minimal harness image for tests/vaultwarden/run.sh.
# The rbw build itself happens at run time against the mounted repo, with
# CARGO_HOME and the target dir on a cache volume, so rebuilds are cheap.
FROM rust:1-slim-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl jq openssh-client python3 python3-cryptography \
    && rm -rf /var/lib/apt/lists/*
