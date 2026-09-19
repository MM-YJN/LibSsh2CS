#!/usr/bin/env python3
"""Capture orchestrator for LibSsh2CS increment 5 packet-framing fixtures.

Spawns a localhost OpenSSH sshd (legacy-enabling all in-scope algorithms), runs
the libssh2 capture harness against it for each framing mode, parses the
combined trace + key-dump output, and writes one fixture set per mode under
tests/LibSsh2CS.UnitTests/Fixtures/packet/.

Each fixture set is a directory named after the framing mode containing:
  key.txt      — the 6 RFC 4253 derived keys (A-F) as hex
  meta.json    — negotiated algorithm names, kex, hostkey, payload, seqno info
  <dir>/       — per-packet files:
    pkt_<n>_<dir>.ct   — ciphertext bytes (raw)
    pkt_<n>_<dir>.pt   — plaintext bytes (raw)
    pkt_<n>.meta.json  — type byte, seqno (inferred), lengths

Direction channels (from libssh2's debugdump):
  "libssh2_transport_write plain" / "plain2" — outbound plaintext (pre-encrypt)
  "libssh2_transport_write send()"          — outbound ciphertext (post-encrypt)
  "libssh2_transport_read() raw"             — inbound ciphertext (raw socket)
  "libssh2_transport_read() plain"           — inbound plaintext (post-decrypt)

The parser correlates plaintext↔ciphertext by stream order within each channel.

Usage:
  ./capture-packets.py [--libssh2-src <path>] [--out <fixtures-dir>]
  Defaults: --libssh2-src ~/repo/libssh2, --out ../../Fixtures/packet

Prerequisites:
  - cmake, gcc, /usr/sbin/sshd (OpenSSH), libssl-dev
  - the instrumented libssh2 build (built by this script if missing)
"""
import argparse
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import Path

# Matches one hexdump line from libssh2's debugdump:
#   "0000: 00 00 00 2C 06 1E 00 00  00 20 78 E4 D4 23 B4 E0 : ...."
# The hex bytes are space-separated, with a DOUBLE space between the 8th and
# 9th byte (libssh2's readability formatting). The regex must tolerate that
# double space, otherwise only the first 8 bytes of each 16-byte line are
# captured (the original `{2}\s?` stops at the un-consumed second space).
# Each hex byte is followed by one-or-more whitespace; the trailing `:` + ASCII
# is not captured (we only want the hex).
HEX_LINE = re.compile(r'^([0-9A-Fa-f]{4}):\s+((?:[0-9A-Fa-f]{2}\s+){1,16})')
HDR_LINE = re.compile(r'^=>\s+(.*?)\s+\((\d+)\s+bytes\)')

# The 5 framing modes to capture. (mode_name, cipher, mac, kex, hostkey)
# For GCM and ChaCha the MAC is integrated; we pass an empty mac to let
# libssh2 pick the AEAD partner (the cipher pins the framing).
MODES = [
    ("cleartext",        "",                          "",  "", ""),  # pre-NEWKEYS only — captures the KEXINIT packets
    ("aes256-ctr_std",   "aes256-ctr",                "",  "", ""),  # default mac hmac-sha2-256
    ("aes256-ctr_etm",   "aes256-ctr",                "hmac-sha2-256-etm@openssh.com", "", ""),
    ("aes256-gcm",       "aes256-gcm@openssh.com",    "",  "", ""),
    ("chacha20-poly1305","chacha20-poly1305@openssh.com", "", "", ""),
]

# The 5 in-scope KEX methods to capture (live oracle for exchange-hash + key
# derivation KATs). Each pins kex + a fixed non-AEAD cipher/MAC so all 6 derived
# keys (A-F) are meaningful. Hostkey is always ssh-ed25519 (orthogonal to kex).
# (method_dir, kex, hash_name, e_field_encoding)
KEX_MODES = [
    ("curve25519-sha256",          "curve25519-sha256",          "SHA-256", "string"),
    ("ecdh-sha2-nistp256",         "ecdh-sha2-nistp256",         "SHA-256", "string"),
    ("ecdh-sha2-nistp384",         "ecdh-sha2-nistp384",         "SHA-384", "string"),
    ("ecdh-sha2-nistp521",         "ecdh-sha2-nistp521",         "SHA-512", "string"),
    ("diffie-hellman-group14-sha256", "diffie-hellman-group14-sha256", "SHA-256", "mpint"),
]

# The 7 in-scope host-key types to capture (increment 8 hostkey-verify oracle).
# Each pins curve25519-sha256 kex + aes256-ctr/hmac-sha2-256 so all 6 derived
# keys are meaningful; only the host-key algorithm varies. The captured K_S + H
# + sig triple is the byte-exact KAT input for HostKeyVerifier.Verify.
# (type_dir, negotiated_hostkey_alg). The sshd config lists all host keys; the
# client pins its preferred hostkey to force negotiation of this single type.
# ssh-rsa (SHA-1) is disabled by default in modern OpenSSH, so its sshd config
# explicitly re-enables it via HostKeyAlgorithms (see write_sshd_config).
HOSTKEY_MODES = [
    ("ssh-ed25519",        "ssh-ed25519"),
    ("ecdsa-sha2-nistp256", "ecdsa-sha2-nistp256"),
    ("ecdsa-sha2-nistp384", "ecdsa-sha2-nistp384"),
    ("ecdsa-sha2-nistp521", "ecdsa-sha2-nistp521"),
    ("rsa-sha2-256",       "rsa-sha2-256"),
    ("rsa-sha2-512",       "rsa-sha2-512"),
    ("ssh-rsa",            "ssh-rsa"),
]

SSHD_PORT = 12222  # high port to avoid conflicts


def run(cmd, **kw):
    print("  $", " ".join(str(c) for c in cmd), file=sys.stderr)
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw)


def free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def build_instrumented_libssh2(libssh2_src, work):
    """Copy libssh2_src, apply the key-dump patch to kex.c, build with debug
    logging + LIBSSH2_PACKET_DUMP. Returns (build_dir, patched_src_dir)."""
    patched = work / "libssh2-patched"
    if patched.exists():
        shutil.rmtree(patched)
    shutil.copytree(libssh2_src, patched)

    kex_c = patched / "src" / "kex.c"
    src = kex_c.read_text()

    # Inject stdio/stdlib/string includes after the libssh2_priv.h include.
    if "#include <stdio.h>" not in src:
        src = src.replace(
            '#include "libssh2_priv.h"',
            '#include "libssh2_priv.h"\n\n#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>',
            1,
        )

    # Inject the KEX-field dump helpers (VC/VS/IC/IS/KS/E/F/K/H) right before
    # the first wrapper function. Gate all output on LIBSSH2_KEX_DUMP so the
    # production build is unaffected. _libssh2_bn/_libssh2_bn_bytes/_libssh2_bn_to_bin
    # are backend macros (OpenSSL: BIGNUM/BN_num_bytes/BN_bn2bin) in scope via kex.c.
    if "cap_dump_kex_dh" not in src:
        helpers = r'''
/* KEX capture-dump helpers — injected by capture-packets.py.
 * Dumps the exchange-hash inputs + output so the C# port can KAT its
 * ComputeExchangeHash + DeriveKey against the reference. Gated on
 * LIBSSH2_KEX_DUMP; no effect on production builds. */
static void cap_dump_bytes(const char *tag, const void *data, size_t len) {
    fprintf(stderr, "PKTDUMP KEX %s %zu", tag, len);
    const unsigned char *p = (const unsigned char *)data;
    for(size_t i = 0; i < len; i++) fprintf(stderr, " %02x", p[i]);
    fprintf(stderr, "\n");
    fflush(stderr);
}
static void cap_dump_bn(const char *tag, _libssh2_bn *bn) {
    size_t n = (size_t)_libssh2_bn_bytes(bn);
    unsigned char *buf = (unsigned char *)malloc(n ? n : 1);
    if(!buf) { fprintf(stderr, "PKTDUMP KEX %s 0\n", tag); return; }
    if(n) _libssh2_bn_to_bin(bn, buf);
    cap_dump_bytes(tag, buf, n);
    free(buf);
}
static void cap_dump_session_fields(LIBSSH2_SESSION *session) {
    /* V_C: local banner — mirrors kex.c:648-668. session->local.banner is often
     * NULL (libssh2 only stores it when set explicitly); the default banner
     * constant carries NO CRLF, while a stored local.banner carries \r\n. */
    if(session->local.banner) {
        size_t vc_len = strlen((const char *)session->local.banner);
        if(vc_len >= 2) vc_len -= 2;  /* strip \r\n */
        cap_dump_bytes("VC", session->local.banner, vc_len);
    }
    else {
        cap_dump_bytes("VC", LIBSSH2_SSH_DEFAULT_BANNER,
                       sizeof(LIBSSH2_SSH_DEFAULT_BANNER) - 1);
    }
    /* V_S: remote banner stored WITHOUT \r\n. */
    cap_dump_bytes("VS", session->remote.banner,
                   strlen((const char *)session->remote.banner));
    cap_dump_bytes("IC", session->local.kexinit, session->local.kexinit_len);
    cap_dump_bytes("IS", session->remote.kexinit, session->remote.kexinit_len);
    cap_dump_bytes("KS", session->server_hostkey, session->server_hostkey_len);
}
static void cap_dump_kex_dh(LIBSSH2_SESSION *session,
                            kmdhgGPshakex_state_t *st, size_t digest_len) {
    if(!getenv("LIBSSH2_KEX_DUMP")) return;
    cap_dump_session_fields(session);
    cap_dump_bn("E", st->e);
    cap_dump_bn("F", st->f);
    cap_dump_bn("K", st->k);
    cap_dump_bytes("H", st->h_sig_comp, digest_len);
    cap_dump_bytes("SIG", st->h_sig, st->h_sig_len);
}
static void cap_dump_kex_ec(LIBSSH2_SESSION *session,
                            const unsigned char *pub, size_t pub_len,
                            const unsigned char *spub, size_t spub_len,
                            kmdhgGPshakex_state_t *st, size_t digest_len) {
    if(!getenv("LIBSSH2_KEX_DUMP")) return;
    cap_dump_session_fields(session);
    cap_dump_bytes("E", pub, pub_len);
    cap_dump_bytes("F", spub, spub_len);
    cap_dump_bn("K", st->k);
    cap_dump_bytes("H", st->h_sig_comp, digest_len);
    cap_dump_bytes("SIG", st->h_sig, st->h_sig_len);
}

'''
        anchor_fn = "static int _libssh2_sha_algo_ctx_init(int sha_algo, void *ctx)"
        if anchor_fn not in src:
            raise RuntimeError("kex.c helper-anchor not found — patch bit-rot")
        src = src.replace(anchor_fn, helpers + anchor_fn, 1)

    # Inject the DH-path dump call after the exchange-hash finalize (success path
    # only — failure does `goto clean_exit`). Anchored on the unique error string.
    if "cap_dump_kex_dh(session, exchange_state" not in src:
        dh_anchor = '''                                 "kex: failed to calculate hash");
            goto clean_exit;
        }

        err = session->hostkey->sig_verify(session,'''
        dh_repl = '''                                 "kex: failed to calculate hash");
            goto clean_exit;
        }

        if(getenv("LIBSSH2_KEX_DUMP")) {
            cap_dump_kex_dh(session, exchange_state, digest_len);
        }

        err = session->hostkey->sig_verify(session,'''
        if dh_anchor not in src:
            raise RuntimeError("kex.c DH exchange-hash anchor not found — patch bit-rot")
        src = src.replace(dh_anchor, dh_repl, 1)

    # Inject the EC-macro dump call after the hash finalize (success path only —
    # failure does `break`). Covers ecdh-sha2-nistp256/384/521 + curve25519-sha256
    # (all four invoke LIBSSH2_KEX_METHOD_EC_SHA_HASH_CREATE_VERIFY).
    if "cap_dump_kex_ec(session, public_key" not in src:
        ec_anchor = (
            "       !libssh2_sha##digest_type##_final(ctx, exchange_state->h_sig_comp)) { \\\n"
            "        rc = -1;                                                             \\\n"
            "        break;                                                               \\\n"
            "    }                                                                        \\\n"
            "                                                                             \\\n"
            "    if(session->hostkey->                                                    \\\n"
        )
        ec_repl = (
            "       !libssh2_sha##digest_type##_final(ctx, exchange_state->h_sig_comp)) { \\\n"
            "        rc = -1;                                                             \\\n"
            "        break;                                                               \\\n"
            "    }                                                                        \\\n"
            "    if(getenv(\"LIBSSH2_KEX_DUMP\")) {                                       \\\n"
            "        cap_dump_kex_ec(session, public_key, public_key_len,                 \\\n"
            "            server_public_key, server_public_key_len, exchange_state,        \\\n"
            "            SHA##digest_type##_DIGEST_LENGTH);                               \\\n"
            "    }                                                                        \\\n"
            "                                                                             \\\n"
            "    if(session->hostkey->                                                    \\\n"
        )
        if ec_anchor not in src:
            raise RuntimeError("kex.c EC exchange-hash anchor not found — patch bit-rot")
        src = src.replace(ec_anchor, ec_repl, 1)

    # Inject the key dump at the end of LIBSSH2_KEX_METHOD_SHA_VALUE_HASH.
    # Anchor: the "} while(0)" that closes the macro, after the SHA final block.
    anchor = """            if(!libssh2_sha##digest_type##_final(hash, (value) + len)) {    \\
                LIBSSH2_FREE(session, value);                               \\
                value = NULL;                                               \\
                break;                                                      \\
            }                                                               \\
            len += SHA##digest_type##_DIGEST_LENGTH;                        \\
        }                                                                   \\
} while(0)"""
    dump = """            if(!libssh2_sha##digest_type##_final(hash, (value) + len)) {    \\
                LIBSSH2_FREE(session, value);                               \\
                value = NULL;                                               \\
                break;                                                      \\
            }                                                               \\
            len += SHA##digest_type##_DIGEST_LENGTH;                        \\
        }                                                                   \\
        if(value && reqlen && version && getenv("LIBSSH2_PACKET_DUMP")) {   \\
            fprintf(stderr, "PKTDUMP KEY %c %zu", (char)(version)[0],        \\
                    (size_t)(reqlen));                                      \\
            for(size_t _i = 0; _i < (size_t)(reqlen); _i++) {               \\
                fprintf(stderr, " %02x", (value)[_i]);                      \\
            }                                                               \\
            fprintf(stderr, "\\n");                                         \\
            fflush(stderr);                                                 \\
        }                                                                   \\
} while(0)"""
    if "PKTDUMP KEY" not in src:
        if anchor not in src:
            raise RuntimeError("kex.c anchor not found — patch bit-rot, fix anchor")
        src = src.replace(anchor, dump, 1)
        kex_c.write_text(src)

    build = work / "libssh2-build"
    build.mkdir(parents=True, exist_ok=True)
    run(["cmake", "-DCRYPTO_BACKEND=OpenSSL", "-DBUILD_SHARED_LIBS=ON",
         "-DBUILD_EXAMPLES=OFF", "-DENABLE_ZLIB_COMPRESSION=OFF",
         "-DENABLE_DEBUG_LOGGING=ON", "-DCMAKE_BUILD_TYPE=Debug",
         "-DCMAKE_C_FLAGS=-DLIBSSH2_PACKET_DUMP",
         str(patched)], cwd=build)
    run(["make", "-j", str(os.cpu_count() or 2)], cwd=build)
    return build / "src", patched


def gen_keys(keysdir):
    """Generate throwaway host + user keys if missing.

    Host keys: ed25519 (always) + RSA-2048 + ECDSA nistp256/384/521 for the
    increment-8 hostkey-verify captures. User key: ed25519 only (auth)."""
    keysdir.mkdir(parents=True, exist_ok=True)
    host = keysdir / "host_ed25519"
    user = keysdir / "user_ed25519"
    auth = keysdir / "authorized_keys"
    if not host.exists():
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "cap-host", "-f", str(host)])
    if not user.exists():
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "cap-user", "-f", str(user)])
        shutil.copy(str(user) + ".pub", str(auth))
    # Additional host keys for the per-hostkey-type capture matrix.
    for algo, label in [("rsa", "4096"), ("ecdsa", "256"), ("ecdsa", "384"), ("ecdsa", "521")]:
        name = keysdir / f"host_{algo}{'' if algo == 'rsa' else label}"
        if not name.exists():
            if algo == "rsa":
                run(["ssh-keygen", "-q", "-t", "rsa", "-b", "4096", "-N", "", "-C", "cap-host-rsa", "-f", str(name)])
            else:
                run(["ssh-keygen", "-q", "-t", "ecdsa", "-b", label, "-N", "", "-C", f"cap-host-{algo}{label}", "-f", str(name)])
    return host, user, auth


def write_sshd_config(keysdir, port, authorized, hostkey_algorithms="ssh-ed25519"):
    """sshd config listing all in-scope algorithms (legacy + modern).

    All generated host keys are loaded so any hostkey algorithm can be negotiated;
    `hostkey_algorithms` filters which the server offers (forcing the capture to
    use that single type). Defaults to ssh-ed25519 for the packet/kex captures."""
    hostkey_lines = []
    for name in ["host_ed25519", "host_rsa", "host_ecdsa256", "host_ecdsa384", "host_ecdsa521"]:
        p = keysdir / name
        if p.exists():
            hostkey_lines.append(f"        HostKey {p}")
    hostkeys = "\n".join(hostkey_lines) if hostkey_lines else f"        HostKey {keysdir}/host_ed25519"
    cfg = keysdir / f"sshd_config.{port}"
    cfg.write_text(textwrap.dedent(f"""\
        Port {port}
        ListenAddress 127.0.0.1
{hostkeys}
        PidFile {keysdir}/sshd.{port}.pid
        UsePAM no
        PasswordAuthentication no
        PubkeyAuthentication yes
        AuthorizedKeysFile {authorized}
        StrictModes no
        LogLevel ERROR
        Ciphers aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc,chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
        MACs hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com
        KexAlgorithms curve25519-sha256,diffie-hellman-group14-sha256,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521
        HostKeyAlgorithms {hostkey_algorithms}
        Subsystem sftp /usr/lib/openssh/sftp-server
    """))
    return cfg


def start_sshd(cfg):
    # Parse the port from the config (so we can wait for it to accept).
    m = re.search(r"Port (\d+)", cfg.read_text())
    port = int(m.group(1)) if m else 0
    pid_file = cfg.parent / f"sshd.{port}.pid"
    # Remove any stale pid file first.
    if pid_file.exists():
        pid_file.unlink()
    subprocess.run(["/usr/sbin/sshd", "-f", str(cfg)], check=True)
    # Wait for the port to accept connections (sshd bound the listener).
    for _ in range(100):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                break
        except OSError:
            time.sleep(0.05)
    else:
        raise RuntimeError(f"sshd did not start listening on port {port}")
    # Read the pid file (it should be populated by now).
    for _ in range(50):
        if pid_file.exists():
            content = pid_file.read_text().strip()
            if content:
                return int(content)
        time.sleep(0.05)
    raise RuntimeError(f"sshd pid file {pid_file} empty/missing after listen")


def kill_sshd(pid):
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    # Reap the zombie so the next sshd can rebind the port cleanly.
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass
    time.sleep(0.1)


def parse_hexdump(lines):
    """Parse a list of hexdump lines (offset: hex hex... : ascii) into bytes."""
    out = bytearray()
    for ln in lines:
        m = HEX_LINE.match(ln)
        if not m:
            continue
        hexpart = m.group(2)
        for b in hexpart.split():
            out.append(int(b, 16))
    return bytes(out)


def parse_capture(trace_text, stderr_text):
    """Parse the combined trace output into structured records.

    Returns:
      keys:   {letter: hex_string}
      packets: list of dicts {dir, channel, plaintext(bytes), ciphertext(bytes)}
      negotiated: {kex, cipher, mac, hostkey} from HANDSHAKE_OK line
    """
    # Parse keys from stderr.
    keys = {}
    for ln in stderr_text.splitlines():
        if ln.startswith("PKTDUMP KEY "):
            parts = ln.split()
            letter = parts[2]
            hexstr = "".join(parts[4:])
            keys[letter] = hexstr

    negotiated = {}
    for ln in stderr_text.splitlines():
        if ln.startswith("HANDSHAKE_OK "):
            # HANDSHAKE_OK kex=X crypt=Y mac=Z hostkey=W
            for kv in ln[len("HANDSHAKE_OK "):].split():
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    negotiated[k] = v

    # Parse the trace into channel-grouped blocks. A block = header line
    # "=> <channel> (N bytes)" followed by hexdump lines until the next
    # header or non-hexdump line.
    blocks = []
    cur = None
    for raw in trace_text.splitlines():
        if not raw.startswith("TRACE: "):
            continue
        ln = raw[len("TRACE: "):]
        m = HDR_LINE.match(ln)
        if m:
            if cur is not None:
                blocks.append(cur)
            cur = {"channel": m.group(1), "nbytes": int(m.group(2)), "hex": []}
        else:
            if cur is not None and HEX_LINE.match(ln):
                cur["hex"].append(ln)
            else:
                if cur is not None:
                    blocks.append(cur)
                    cur = None
    if cur is not None:
        blocks.append(cur)

    for b in blocks:
        b["bytes"] = parse_hexdump(b["hex"])

    # Correlate outbound plaintext↔ciphertext by stream order. The "write plain"
    # + "write plain2" are two segments of one logical outbound plaintext (plain2
    # follows plain); pair the concatenation with the next "write send()" block.
    #
    # Only outbound packets are committed: the "write send()" (post-encrypt) and
    # "write plain" (pre-encrypt) channels alternate strictly 1:1, giving a
    # reliable plaintext↔ciphertext oracle. Inbound ("read() raw" / "read()
    # plain") do NOT alternate 1:1 — a single raw socket read can buffer several
    # packets' ciphertext, feeding multiple subsequent "read() plain" blocks —
    # so the raw↔plain correlation is ambiguous without re-parsing the SSH
    # framing. Rather than implement a ciphertext framing parser here, the
    # PacketReader tests reuse the OUTBOUND ciphertext: feed it through the
    # reader configured with the outbound keys (A=IV, C=enc, E=MAC) and seqno=0,
    # and assert the reader produces the outbound plaintext. This validates the
    # reader's decrypt/verify/decompress path against real libssh2 ciphertext
    # without needing the (unreliable) inbound correlation.
    packets = []
    ob_pt_segments = []  # accumulating plaintext segments (plain + plain2)

    for b in blocks:
        ch = b["channel"]
        data = b["bytes"]
        nbytes = b["nbytes"]
        # Truncate/validate: hexdump may include extra bytes; trust nbytes.
        if len(data) > nbytes:
            data = data[:nbytes]

        if ch == "libssh2_transport_write plain" or ch == "libssh2_transport_write plain2":
            ob_pt_segments.append(data)
        elif ch == "libssh2_transport_write send()":
            pt = b"".join(ob_pt_segments)
            ob_pt_segments = []
            packets.append({"dir": "out", "plaintext": pt, "ciphertext": data})
        # Inbound "read() raw" / "read() plain" blocks are discarded (see note
        # above) — the reader oracle is built from the outbound channel.

    return {"keys": keys, "packets": packets, "negotiated": negotiated}


def write_mode_fixtures(out_root, mode_name, parsed, cipher, mac, kex, hostkey):
    """Write the fixture files for one mode. For 'cleartext' we keep only the
    pre-NEWKEYS (unencrypted) packets; for the encrypted modes we keep only the
    post-NEWKEYS encrypted packets (the first NEWKEYS packet is the boundary).
    """
    mode_dir = out_root / mode_name
    if mode_dir.exists():
        shutil.rmtree(mode_dir)
    mode_dir.mkdir(parents=True)

    # key.txt — one line per letter: "<letter> <hex>"
    with (mode_dir / "key.txt").open("w") as f:
        for letter in sorted(parsed["keys"]):
            f.write(f"{letter} {parsed['keys'][letter]}\n")

    # meta.json — top-level mode metadata
    #
    # Oracle design: the committed ciphertext is the OUTBOUND (client→server)
    # stream produced by libssh2, encrypted with the "local" keys A=IV, C=enc,
    # E=MAC. The PacketReader tests feed this ciphertext through the reader
    # configured with those local keys (and seqno=0, which is the post-NEWKEYS
    # starting seqno for both directions). This validates the reader's
    # decrypt/verify/decompress path against real libssh2-produced ciphertext.
    # The PacketWriter tests feed the plaintext through the writer and assert
    # the output matches this ciphertext (modulo random padding — see the
    # writer tests, which compare via decrypt-round-trip rather than byte
    # equality, OR pin the padding RNG for byte-exact comparison).
    meta = {
        "mode": mode_name,
        "cipher": cipher or "(default)",
        "mac": mac or "(default)",
        "kex": kex or "(default)",
        "hostkey": hostkey or "(default)",
        "negotiated": parsed["negotiated"],
        "oracle": "outbound — reader uses local keys A=IV, C=enc, E=MAC, seqno=0",
        "reader_keys": {"iv": "A", "enc": "C", "mac": "E"},
        "packets": [],
    }

    pkts = parsed["packets"]
    # Filter: for 'cleartext' keep only unencrypted (pre-NEWKEYS). For others,
    # keep only encrypted (post-NEWKEYS). The NEWKEYS packet (type 21) is the
    # boundary; we detect it by type byte in the plaintext. For 'cleartext' mode
    # we have no encryption at all (it's the initial KEXINIT), so keep all.
    seen_newkeys = False
    kept = []
    for p in pkts:
        pt = p["plaintext"]
        ptype = pt[0] if pt else -1
        if mode_name == "cleartext":
            kept.append(p)
            continue
        # encrypted modes: skip packets before/at NEWKEYS; keep post-NEWKEYS.
        if ptype == 21:  # SSH_MSG_NEWKEYS
            seen_newkeys = True
            continue
        if not seen_newkeys:
            continue
        kept.append(p)

    for i, p in enumerate(kept):
        pt = p["plaintext"]
        ct = p["ciphertext"]
        direction = p["dir"]
        (mode_dir / f"pkt_{i}_{direction}.pt").write_bytes(pt)
        (mode_dir / f"pkt_{i}_{direction}.ct").write_bytes(ct)
        meta["packets"].append({
            "index": i,
            "direction": direction,
            "type_byte": pt[0] if pt else -1,
            "plaintext_len": len(pt),
            "ciphertext_len": len(ct),
        })

    (mode_dir / "meta.json").write_text(json.dumps(meta, indent=2))
    print(f"  wrote {mode_name}: {len(kept)} packets, keys={list(parsed['keys'])}",
          file=sys.stderr)


def parse_kex_dump(stderr_text):
    """Parse PKTDUMP KEX <field> <len> <hex...> lines into {field: bytes}.

    Also returns the A-F derived keys (from PKTDUMP KEY lines) under 'keys'.
    Fields: VC, VS, IC, IS, KS, E, F, K, H.
    """
    fields = {}
    keys = {}
    for ln in stderr_text.splitlines():
        if ln.startswith("PKTDUMP KEX "):
            parts = ln.split()
            tag = parts[2]
            n = int(parts[3])
            hexstr = "".join(parts[4:])
            data = bytes.fromhex(hexstr)
            assert len(data) == n, f"{tag}: stated len {n} != hex len {len(data)}"
            fields[tag] = data
        elif ln.startswith("PKTDUMP KEY "):
            parts = ln.split()
            letter = parts[2]
            keys[letter] = "".join(parts[4:])
    return {"fields": fields, "keys": keys}


def write_kex_fixtures(out_root, method_dir, kex, hash_name, e_field, parsed,
                      cipher, mac, hostkey):
    """Write the Fixtures/kex/<method>/ oracle from a parsed KEX dump."""
    f = parsed["fields"]
    required = ["VC", "VS", "IC", "IS", "KS", "E", "F", "K", "H"]
    missing = [r for r in required if r not in f]
    if missing:
        raise RuntimeError(f"kex capture for {method_dir} missing fields: {missing}")

    d = out_root / method_dir
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True)

    # version_strings.txt — VC/VS as text (banner without CRLF).
    vc = f["VC"].decode("ascii", errors="replace")
    vs = f["VS"].decode("ascii", errors="replace")
    (d / "version_strings.txt").write_text(f"VC={vc}\nVS={vs}\n")

    # Raw binary fields (exact bytes that the C# port re-encodes into the hash).
    (d / "client_kexinit.bin").write_bytes(f["IC"])
    (d / "server_kexinit.bin").write_bytes(f["IS"])
    (d / "host_key.bin").write_bytes(f["KS"])
    (d / "client_ephemeral.bin").write_bytes(f["E"])   # raw e (DH) or Q_C point (ECDH/25519)
    (d / "server_ephemeral.bin").write_bytes(f["F"])   # raw f (DH) or Q_S point (ECDH/25519)
    (d / "shared_secret.bin").write_bytes(f["K"])       # raw big-endian K (pre-mpint)
    (d / "exchange_hash.bin").write_bytes(f["H"])       # oracle H

    # derived_keys.json — A-F from the KEY dump (oracle for the key-derivation KAT).
    dk = {letter: parsed["keys"][letter] for letter in sorted(parsed["keys"])}

    meta = {
        "kex": kex,
        "hostkey": hostkey,
        "cipher_cs": cipher,
        "cipher_sc": cipher,
        "mac_cs": mac,
        "mac_sc": mac,
        "compression": "none",
        "hash": hash_name,
        "e_field_encoding": e_field,            # "mpint" (DH) or "string" (ECDH/curve25519)
        "session_id_equals_h": True,            # all captures are first-kex
        "hash_length": len(f["H"]),
        "field_lengths": {k: len(v) for k, v in f.items()},
        "derived_keys": dk,
    }
    (d / "meta.json").write_text(json.dumps(meta, indent=2))
    print(f"  wrote kex/{method_dir}: hash={hash_name} ({len(f['H'])}B), "
          f"keys={list(parsed['keys'])}", file=sys.stderr)


def write_hostkey_fixtures(out_root, type_dir, hostkey, parsed):
    """Write the Fixtures/hostkey/<type>/ oracle for increment-8 hostkey verify.

    Three byte-exact inputs to HostKeyVerifier.Verify: the server host-key blob
    K_S, the exchange hash H (the signed message), and the raw signature blob.
    """
    f = parsed["fields"]
    required = ["KS", "H", "SIG"]
    missing = [r for r in required if r not in f]
    if missing:
        raise RuntimeError(f"hostkey capture for {type_dir} missing fields: {missing}")

    d = out_root / type_dir
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True)

    (d / "host_key.bin").write_bytes(f["KS"])
    (d / "exchange_hash.bin").write_bytes(f["H"])
    (d / "sig.bin").write_bytes(f["SIG"])

    meta = {
        "hostkey": hostkey,
        "kex": "curve25519-sha256",
        "hash": "SHA-256",
        "field_lengths": {k: len(v) for k, v in f.items()},
    }
    (d / "meta.json").write_text(json.dumps(meta, indent=2))
    print(f"  wrote hostkey/{type_dir}: KS={len(f['KS'])}B, "
          f"H={len(f['H'])}B, SIG={len(f['SIG'])}B", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--libssh2-src", default=os.path.expanduser("~/repo/libssh2"),
                    help="upstream libssh2 checkout to patch + build")
    ap.add_argument("--out", default="Fixtures/packet",
                    help="output fixtures dir (relative to script)")
    ap.add_argument("--work", default=None,
                    help="scratch dir for builds + keys (default: tempdir)")
    ap.add_argument("--capture-bin", default=None,
                    help="pre-built capture harness binary (default: build it)")
    ap.add_argument("--sections", default="packet,kex,hostkey",
                    help="comma-separated capture sections to run: packet,kex,hostkey")
    args = ap.parse_args()
    sections = set(s.strip() for s in args.sections.split(",") if s.strip())

    here = Path(__file__).resolve().parent
    out_root = (here.parent / "Fixtures" / "packet").resolve() if args.out == "Fixtures/packet" else Path(args.out)
    work = Path(args.work) if args.work else Path(tempfile.mkdtemp(prefix="libssh2-cap-"))
    work.mkdir(parents=True, exist_ok=True)
    print(f"work dir: {work}", file=sys.stderr)
    print(f"out dir:  {out_root}", file=sys.stderr)

    if not Path(args.libssh2_src).is_dir():
        print(f"ERROR: libssh2 src not found at {args.libssh2_src}", file=sys.stderr)
        return 2

    # 1. Build instrumented libssh2.
    lib_dir, patched_src = build_instrumented_libssh2(Path(args.libssh2_src), work)
    print(f"built libssh2: {lib_dir}", file=sys.stderr)

    # 2. Build the capture harness.
    capture_c = here / "capture.c"
    if args.capture_bin:
        capture_bin = Path(args.capture_bin)
    else:
        capture_bin = work / "capture"
        run(["gcc", "-I", str(patched_src / "include"),
             "-L", str(lib_dir), str(capture_c),
             "-lssh2", "-lssl", "-lcrypto", "-o", str(capture_bin)])
    print(f"capture harness: {capture_bin}", file=sys.stderr)

    # 3. Generate throwaway keys (sshd config is written per-mode below).
    keysdir = work / "keys"
    host_key, user_key, authorized = gen_keys(keysdir)

    # 4. Capture each mode.
    out_root.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, LIBSSH2_PACKET_DUMP="1")
    ldpath = str(lib_dir) + ":" + env.get("LD_LIBRARY_PATH", "")
    env["LD_LIBRARY_PATH"] = ldpath

    payload = "echo CAPTURE_PAYLOAD_INCREMENT5"
    if "packet" in sections:
        for mode_name, cipher, mac, kex, hostkey in MODES:
            print(f"\n=== capturing {mode_name} ===", file=sys.stderr)
            # Fresh port + config per mode to avoid any port-reuse race.
            port = free_port()
            cfg = write_sshd_config(keysdir, port, str(authorized))
            pid = start_sshd(cfg)
            try:
                proc = subprocess.run(
                    [str(capture_bin), "127.0.0.1", str(port), os.environ.get("USER", "nobody"),
                     str(user_key), cipher, mac, kex, hostkey, payload],
                    env=env, capture_output=True, text=True, timeout=30)
                if proc.returncode != 0:
                    print(f"  harness failed (rc={proc.returncode})", file=sys.stderr)
                    print(proc.stderr, file=sys.stderr)
                    continue
                parsed = parse_capture(proc.stdout, proc.stderr)
                write_mode_fixtures(out_root, mode_name, parsed,
                                    cipher, mac, kex, hostkey)
            finally:
                kill_sshd(pid)

    # 5. Capture each KEX method (exchange-hash + key-derivation oracle).
    kex_out = (here.parent / "Fixtures" / "kex").resolve()
    kex_out.mkdir(parents=True, exist_ok=True)
    # Fixed cipher/MAC so all 6 derived keys (A-F) are meaningful (non-AEAD).
    kex_cipher = "aes256-ctr"
    kex_mac = "hmac-sha2-256"
    kex_hostkey = "ssh-ed25519"
    env["LIBSSH2_KEX_DUMP"] = "1"  # gate the KEX-field dump in the patched kex.c
    if "kex" in sections:
        for method_dir, kex, hash_name, e_field in KEX_MODES:
            print(f"\n=== capturing kex/{method_dir} ===", file=sys.stderr)
            port = free_port()
            cfg = write_sshd_config(keysdir, port, str(authorized))
            pid = start_sshd(cfg)
            try:
                proc = subprocess.run(
                    [str(capture_bin), "127.0.0.1", str(port), os.environ.get("USER", "nobody"),
                     str(user_key), kex_cipher, kex_mac, kex, kex_hostkey, payload],
                    env=env, capture_output=True, text=True, timeout=30)
                if proc.returncode != 0:
                    print(f"  kex harness failed (rc={proc.returncode})", file=sys.stderr)
                    print(proc.stderr, file=sys.stderr)
                    continue
                parsed = parse_kex_dump(proc.stderr)
                write_kex_fixtures(kex_out, method_dir, kex, hash_name, e_field, parsed,
                                  kex_cipher, kex_mac, kex_hostkey)
            finally:
                kill_sshd(pid)

    # 6. Capture each host-key type (K_S + H + sig oracle for increment-8 verify).
    hk_out = (here.parent / "Fixtures" / "hostkey").resolve()
    hk_out.mkdir(parents=True, exist_ok=True)
    # Fixed kex/cipher/mac so the only variable is the host-key algorithm. curve25519
    # is OpenSSH's default and orthogonal to hostkey verify.
    hk_kex = "curve25519-sha256"
    hk_cipher = "aes256-ctr"
    hk_mac = "hmac-sha2-256"
    if "hostkey" in sections:
        for type_dir, hostkey_alg in HOSTKEY_MODES:
            print(f"\n=== capturing hostkey/{type_dir} ===", file=sys.stderr)
            port = free_port()
            # Force the server to offer ONLY this host-key type, so negotiation picks it.
            cfg = write_sshd_config(keysdir, port, str(authorized), hostkey_algorithms=hostkey_alg)
            pid = start_sshd(cfg)
            try:
                proc = subprocess.run(
                    [str(capture_bin), "127.0.0.1", str(port), os.environ.get("USER", "nobody"),
                     str(user_key), hk_cipher, hk_mac, hk_kex, hostkey_alg, payload],
                    env=env, capture_output=True, text=True, timeout=30)
                if proc.returncode != 0:
                    print(f"  hostkey harness failed (rc={proc.returncode})", file=sys.stderr)
                    print(proc.stderr, file=sys.stderr)
                    continue
                parsed = parse_kex_dump(proc.stderr)
                write_hostkey_fixtures(hk_out, type_dir, hostkey_alg, parsed)
            finally:
                kill_sshd(pid)

    print("\nDone.", file=sys.stderr)
    print(f"Fixtures under: {out_root}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())