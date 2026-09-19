#!/usr/bin/env bash
# Regenerates the LibSsh2CS golden fixture corpus.
#
# Usage: ./generate-goldens.sh [path-to-libssh2] [path-to-libgit2]
# Defaults:  libssh2 at ~/repo/libssh2,  libgit2 at ~/repo/libgit2
#
# This is the Phase 1 skeleton. Per-increment population lands with each task:
#   increment 1-2 (crypto):   NO fixture extraction. X25519/Ed25519 use the
#                             compiled-in RFC 7748 §5.2/§6.1 and RFC 8032 §7.1
#                             test vectors (see tests/.../Crypto/*Tests.cs).
#   increment 3 (chacha/poly/dh): Poly1305 = RFC 8439 §2.5.2 (compiled in).
#                             ChaCha20 + ChaChaPolySsh = goldens captured from
#                             the upstream chacha.c / cipher-chachapoly.c (the
#                             Bernstein 8-byte-nonce variant has NO RFC vector —
#                             see /tmp/opencode/golden harness). DH group14 =
#                             two-party self-convergence (RFC 3526 ships no KAT).
#                             All compiled in; this script only re-derives them.
#   increment 5 (packet framing): canned byte captures of one packet per framing
#                             mode (standard CBC/CTR, ETM, AES-GCM, ChaCha20).
#   increment 6-7 (KEX):      canned KEXINIT captures + a captured e/f/K/H set
#                             for the exchange-hash + key-derivation KATs.
#   increment 8 (hostkey/e2e): real hostkey blob + signature + H per hostkey
#                             type, captured from a localhost OpenSSH handshake.
#
# Captures are produced by recording a real OpenSSH (or libssh2 client) handshake
# and dumping the relevant plaintext-before-encryption fields. They are NOT
# extracted verbatim from the libssh2 source tree (libssh2 ships no wire
# fixtures). The upstream libssh2/libgit2 checkouts are only consulted to confirm
# expected algorithm-preference strings and message layouts.
#
# Idempotent: re-running overwrites in place.

set -euo pipefail

LIBSSH2="${1:-$HOME/repo/libssh2}"
LIBGIT2="${2:-$HOME/repo/libgit2}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURES="$SCRIPT_DIR/Fixtures"

mkdir -p "$FIXTURES"

# ---------------------------------------------------------------------------
# Upstream sanity checks (informational only — captures are not copied).
# ---------------------------------------------------------------------------
if [[ ! -d "$LIBSSH2/src" ]]; then
    echo "warning: libssh2 checkout not found at $LIBSSH2 (canned-capture" >&2
    echo "         generation for increments 5-8 needs a working ssh-keygen" >&2
    echo "         + sshd, not the libssh2 source)" >&2
fi

# ---------------------------------------------------------------------------
# increment 5 (packet framing) — DONE. Capture pipeline:
#   Capture/capture-packets.py --libssh2-src ~/repo/libssh2 --out Fixtures/packet
#
# It builds an instrumented libssh2 (debug logging + a getenv("LIBSSH2_PACKET_DUMP")
# -gated key dump in kex.c's LIBSSH2_KEX_METHOD_SHA_VALUE_HASH macro), runs a
# localhost OpenSSH sshd with a legacy-enabling config, drives the harness per
# framing mode, and parses libssh2's trace output into per-mode fixtures:
#   Fixtures/packet/<mode>/key.txt        — 6 RFC 4253 derived keys (A-F) as hex
#   Fixtures/packet/<mode>/meta.json      — negotiated algs + per-packet index
#   Fixtures/packet/<mode>/pkt_<n>_out.ct — outbound ciphertext (post-encrypt)
#   Fixtures/packet/<mode>/pkt_<n>_out.pt — outbound plaintext  (pre-encrypt)
#
# Modes captured: cleartext (pre-NEWKEYS KEXINIT), aes256-ctr_std,
# aes256-ctr_etm, aes256-gcm, chacha20-poly1305. Oracle is the OUTBOUND stream
# (client->server, encrypted with local keys A/C/E); the PacketReader tests
# feed it through the reader with those keys + seqno=0. See meta.json "oracle".
#
# Re-run when upstream libssh2 behaviour changes or a new framing mode is added.
# Requires: cmake, gcc, /usr/sbin/sshd (OpenSSH), libssl-dev. Fixtures are
# committed; CI never runs this script.

# ---------------------------------------------------------------------------
# increment 6-7 (KEX) — DONE. Capture pipeline (same harness as increment 5):
#   Capture/capture-packets.py --libssh2-src ~/repo/libssh2 --out Fixtures/packet
#
# The instrumented libssh2 build now carries a SECOND getenv("LIBSSH2_KEX_DUMP")
# -gated patch (in kex.c) that dumps the exchange-hash inputs + output from
# inside the DH / ECDH / curve25519 hash-finalize sites. The harness runs 5
# kex-pinned handshakes (one per in-scope method) and writes:
#   Fixtures/kex/<method>/version_strings.txt    — V_C, V_S (banner, no CRLF)
#   Fixtures/kex/<method>/client_kexinit.bin     — I_C (full payload, incl type byte)
#   Fixtures/kex/<method>/server_kexinit.bin     — I_S
#   Fixtures/kex/<method>/host_key.bin           — K_S (server host key blob)
#   Fixtures/kex/<method>/client_ephemeral.bin   — e (DH raw BE) or Q_C (ECDH/25519 point)
#   Fixtures/kex/<method>/server_ephemeral.bin   — f (DH raw BE) or Q_S
#   Fixtures/kex/<method>/shared_secret.bin      — K (raw big-endian, pre-mpint)
#   Fixtures/kex/<method>/exchange_hash.bin      — H oracle
#   Fixtures/kex/<method>/meta.json              — negotiated algs + hash + e_field_encoding
#                                                  + derived_keys (A-F, for the key-derivation KAT)
#
# Methods captured: curve25519-sha256 (SHA-256), ecdh-sha2-nistp256 (SHA-256),
# ecdh-sha2-nistp384 (SHA-384), ecdh-sha2-nistp521 (SHA-512),
# diffie-hellman-group14-sha256 (SHA-256). All pinned to ssh-ed25519 hostkey +
# aes256-ctr/hmac-sha2-256 so all 6 derived keys are meaningful. session_id == H
# (all captures are first-kex). The exchange-hash + key-derivation KATs both
# reproduce byte-exact from these fixtures (verified at capture time).

# ---------------------------------------------------------------------------
# TODO increment 8 (hostkey + end-to-end):
# For each ssh-{ed25519,rsa-sha2-256,rsa-sha2-512,ecdsa-sha2-nistp256} host key:
#   - host key blob (K_S)         -> $FIXTURES/hostkey/<type>_blob.bin
#   - signature blob (h_sig)      -> $FIXTURES/hostkey/<type>_sig.bin
#   - exchange hash it signs (H)  -> $FIXTURES/hostkey/<type>_hash.bin
# Captured from a localhost sshd with each key type configured. The end-to-end
# Docker test is the live cross-check.

# ---------------------------------------------------------------------------
# Phase 3.6 — known_hosts parity fixtures (ssh-keygen produced).
#
# Produces a corpus of known_hosts lines for all 5 in-scope host key types in
# both plain and `ssh-keygen -H` hashed forms, plus the raw wire-format key
# blobs (base64-decoded) for byte-exact Check parity. Used by
# KnownHostsFixtureTests.
#
# Pipeline (NO sshd needed — the .pub files produced by ssh-keygen have the
# exact same wire format as known_hosts entries; ssh-keyscan only fetches one
# ECDSA curve per call so we'd lose nistp384/521, hence the .pub-file path):
#
#   for each type in (ed25519, rsa, ecdsa256, ecdsa384, ecdsa521):
#     ssh-keygen -t <alg> -f <keyfile>      # generates <keyfile>.pub
#     awk '{print $2}' <keyfile>.pub | base64 -d > <type>_blob.bin
#
#   assemble keyscan_plain.txt: <host> <wire-type> <base64> per line
#   cp keyscan_plain.txt keyscan_hashed.txt && ssh-keygen -H -f keyscan_hashed.txt
#   emit meta.json with { host, port, types: [{wireName, blob, knownHostKeyType}] }
#
# Re-run when a new in-scope host key type is added or when sha1 host hashing
# behaviour changes upstream. Requires: ssh-keygen. Fixtures are committed; CI
# never runs this script.

generate_known_hosts_fixtures() {
    local out="$FIXTURES/known_hosts"
    local work
    work="$(mktemp -d)"
    trap 'rm -rf "$work"' RETURN

    mkdir -p "$out"

    # The host/port recorded in the corpus. Non-default port so the bracketed
    # `[host]:port` form is exercised in every entry (matches ssh-keygen -H
    # output and the Check `[host]:port`-form-preferred-over-plain test).
    local host="127.0.0.1"
    local port=2222
    local host_form="[${host}]:${port}"

    # Algorithms to generate. The `keygen_args` are passed to `ssh-keygen -t`;
    # the `wire_name` is the SSH wire algorithm name; the `blob_name` is the
    # output filename; `khk_type` is the KnownHostKeyType enum value.
    #
    # Order matches the existing KnownHostsSha1CheckTests priority claim
    # (ed25519 first; ecdsa by curve size; rsa last) so iteration order is
    # natural for a downstream priority-probe test.
    local entries=(
        "ed25519:ssh-ed25519:ed25519_blob.bin:Ed25519"
        "ecdsa -b 256:ecdsa-sha2-nistp256:ecdsa256_blob.bin:Ecdsa256"
        "ecdsa -b 384:ecdsa-sha2-nistp384:ecdsa384_blob.bin:Ecdsa384"
        "ecdsa -b 521:ecdsa-sha2-nistp521:ecdsa521_blob.bin:Ecdsa521"
        "rsa -b 2048:ssh-rsa:rsa_blob.bin:SshRsa"
    )

    local plain_lines=()
    local meta_types=""

    local first=1
    for entry in "${entries[@]}"; do
        local keygen_args wire_name blob_name khk_type
        IFS=':' read -r keygen_args wire_name blob_name khk_type <<<"$entry"

        local keyfile="$work/${blob_name%.bin}"
        # shellcheck disable=SC2086  # intentional word-splitting of keygen_args
        ssh-keygen -q -N "" -C "" -f "$keyfile" -t $keygen_args

        local pub_file="$keyfile.pub"
        if [[ ! -s "$pub_file" ]]; then
            echo "error: ssh-keygen did not produce $pub_file" >&2
            return 1
        fi

        # Extract the base64 (field 2) and decode to the raw wire blob.
        local base64_blob
        base64_blob="$(awk '{print $2}' "$pub_file")"
        echo -n "$base64_blob" | base64 -d > "$out/$blob_name"

        # Emit the plain known_hosts line: <host> <wire-type> <base64>
        plain_lines+=("${host_form} ${wire_name} ${base64_blob}")

        # Accumulate meta.json types array.
        if [[ $first -eq 0 ]]; then meta_types+=","; fi
        first=0
        meta_types+=$(printf '
      { "wireName": "%s", "blob": "%s", "knownHostKeyType": "%s" }' \
            "$wire_name" "$blob_name" "$khk_type")
    done

    # Plain known_hosts file.
    : > "$out/keyscan_plain.txt"
    for line in "${plain_lines[@]}"; do
        printf '%s\n' "$line" >> "$out/keyscan_plain.txt"
    done

    # Hashed copy. `ssh-keygen -H` rewrites in place, preserving the original
    # as `<file>.old`; remove the .old backup (fixture-only; we control the
    # hostname so there's no privacy concern).
    cp "$out/keyscan_plain.txt" "$out/keyscan_hashed.txt"
    ssh-keygen -H -f "$out/keyscan_hashed.txt" >/dev/null 2>&1
    rm -f "$out/keyscan_hashed.txt.old"

    # meta.json — the test uses this to know the recorded host/port and to
    # map blob filenames back to KnownHostKeyType values.
    cat > "$out/meta.json" <<EOF
{
  "host": "${host}",
  "port": ${port},
  "hostForm": "${host_form}",
  "types": [${meta_types}
  ]
}
EOF

    echo "known_hosts fixtures: $(ls "$out" | wc -l) files in $out"
}

if [[ "${1:-}" != "--skip-known-hosts" ]]; then
    generate_known_hosts_fixtures
fi

echo "Skeleton ready. Population TODOs land with increments 5-8."
echo "(Increments 1-2 — X25519/Ed25519 crypto — use compiled-in RFC vectors.)"
echo "Run: $(dirname "$0")/Capture/capture-packets.py --libssh2-src $LIBSSH2"
