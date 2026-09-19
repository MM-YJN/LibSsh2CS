using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

using LibSsh2CS.Crypto;
using LibSsh2CS.Util;

namespace LibSsh2CS.Transport;

/// <summary>
/// Server host-key signature verification during key exchange. Parses the host
/// key blob <c>K_S</c> and the signature blob produced by the server, and
/// verifies the signature over the exchange hash <c>H</c>. Port of libssh2's
/// <c>hostkey.c</c> <c>*_init</c> + <c>*_sig_verify</c> functions plus the
/// OpenSSL backend <c>_libssh2_rsa_sha2_verify</c> / <c>_libssh2_ecdsa_verify</c>
/// / <c>_libssh2_ed25519_verify</c>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Parity-critical: the negotiated <see cref="SshHostKeyType"/> drives the
/// verify path.</b> libssh2 dispatches via the negotiated method's function
/// pointer (<c>session-&gt;hostkey-&gt;sig_verify</c>, <c>kex.c:746</c>); it does
/// NOT derive the hash from the signature blob. This matters for RSA: RFC 8332
/// keeps the host-key blob's type string as <c>"ssh-rsa"</c> even when the key
/// signs with <c>rsa-sha2-256</c>/<c>rsa-sha2-512</c>, so the hash cannot be
/// inferred from <c>K_S</c> — only from the negotiated algorithm.
/// </para>
/// <para>
/// <b>The verified message is the exchange hash <c>H</c> itself</b> (passed as
/// <c>m</c> to <c>sig_verify</c>, <c>kex.c:746-750</c>). RSA / ECDSA backends
/// hash <c>H</c> once more (SHA-1/256/384/512) before the public-key verify;
/// Ed25519 verifies over the raw <c>H</c> (its internal SHA-512 applies).
/// </para>
/// <para>
/// <b>Sig-blob parsing: uniform
/// <c>string name + string body</c> parse for all types, with the embedded name
/// validated against the negotiated type.</b> This is wire-identical to
/// libssh2's fixed-offset skip (RSA/Ed25519) and name-parse (ECDSA), but adds
/// defense-in-depth: libssh2's <c>init</c> already validates <c>K_S</c>'s name;
/// we extend that check to the signature blob too. A mismatched name is treated
/// as a verification failure (libssh2 returns <c>-1</c> from <c>init</c>).
/// </para>
/// <para>
/// sig_blob wire formats (from <c>hostkey.c *_sig_verify</c>):
/// <list type="bullet">
/// <item><c>ssh-rsa</c> / <c>rsa-sha2-256</c> / <c>rsa-sha2-512</c>:
///   <c>string &lt;name&gt; + string &lt;raw RSA sig&gt;</c> — PKCS#1 v1.5 over
///   <c>SHA{1,256,512}(H)</c>.</item>
/// <item><c>ecdsa-sha2-nistpXXX</c>: <c>string &lt;name&gt; + string(string r + string s)</c>
///   — <c>r</c>/<c>s</c> are big-endian integers, DER-reconstructed and verified
///   over <c>SHA{256,384,512}(H)</c>.</item>
/// <item><c>ssh-ed25519</c>: <c>string &lt;name&gt; + string &lt;64-byte sig&gt;</c>
///   — <c>Ed25519.Verify</c> over raw <c>H</c>.</item>
/// </list>
/// </para>
/// </remarks>
internal static class HostKeyVerifier
{
    private const int Ed25519SigLen = 64;
    private const int Ed25519PubkeyLen = 32;

    /// <summary>
    /// Verifies a server host-key signature over the exchange hash.
    /// </summary>
    /// <param name="hostKey">The server host-key blob <c>K_S</c> (as parsed from
    /// KEXDH_REPLY).</param>
    /// <param name="exchangeHash">The exchange hash <c>H</c> — the signed message.</param>
    /// <param name="sigBlob">The raw signature blob (the SSH <c>string</c> following
    /// <c>K_S</c>/<c>Q_S</c> in KEXDH_REPLY).</param>
    /// <param name="type">The negotiated host-key algorithm — selects the verify
    /// path and hash. MUST match the <c>K_S</c> / sig-blob type strings.</param>
    /// <returns><c>true</c> if the signature is valid; <c>false</c> on any parse
    /// failure, type mismatch, or failed verify (mirrors libssh2's <c>-1</c> →
    /// <c>false</c> collapse; the caller raises <c>KeyExchangeFailure</c>).</returns>
    public static bool Verify(byte[] hostKey, byte[] exchangeHash, byte[] sigBlob, SshHostKeyType type)
    {
        // All parse/verify failures collapse to false; the caller (RunExchangeAsync's
        // verify callback) raises KeyExchangeFailure. This mirrors libssh2, where a
        // -1 from init/sig_verify propagates as LIBSSH2_ERROR_HOSTKEY_SIGN.
        try
        {
            return type switch
            {
                SshHostKeyType.SshRsa or SshHostKeyType.RsaSha256 or SshHostKeyType.RsaSha512
                    => VerifyRsa(hostKey, exchangeHash, sigBlob, type),
                SshHostKeyType.Ecdsa256 or SshHostKeyType.Ecdsa384 or SshHostKeyType.Ecdsa521
                    => VerifyEcdsa(hostKey, exchangeHash, sigBlob, type),
                SshHostKeyType.Ed25519
                    => VerifyEd25519(hostKey, exchangeHash, sigBlob),
                _ => false,
            };
        }
        catch (Exception ex) when (ex is SshException
            or CryptographicException
            or ArgumentException
            or IndexOutOfRangeException
            or PlatformNotSupportedException)
        {
            // Wire-parse errors (truncation, bad length) from PacketWireReader are
            // verification failures, not crashes — same as libssh2 returning -1.
            // BCL import/verify calls can also throw for attacker-controlled
            // RSA/ECDSA key material; all of those must collapse to false
            // rather than escape as unexpected exception types.
            return false;
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // RSA: ssh-rsa (SHA-1) / rsa-sha2-256 / rsa-sha2-512
    // ════════════════════════════════════════════════════════════════════════

    private static bool VerifyRsa(byte[] hostKey, byte[] exchangeHash, byte[] sigBlob, SshHostKeyType type)
    {
        if (!TryReadSigBody(sigBlob, type, out byte[] rsaSig))
        {
            return false;
        }

        // K_S = string "ssh-rsa"(or rsa-sha2-*) + string e + string n. The init
        // function accepts all three RSA names (hostkey.c:91-111); validate that
        // the K_S name is one of them.
        var ks = new PacketWireReader(new ReadOnlySequence<byte>(hostKey));
        if (!IsRsaName(ks.ReadString()))
        {
            return false;
        }

        byte[] e = ks.ReadBlob();
        byte[] n = ks.ReadBlob();

        // _libssh2_rsa_sha2_verify (openssl.c:418) hashes m (=H) with SHA-1/256/512
        // then RSA_verify (PKCS#1 v1.5). BCL RSA.VerifyHash takes the precomputed
        // digest + the algorithm name (for the DigestInfo OID) — equivalent to
        // RSA_verify(nid, hash, ...).
        HashAlgorithmName hash = RsaHash(type);
        byte[] digest = HashData(hash, exchangeHash);
        using var rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters { Exponent = e, Modulus = n });
        return rsa.VerifyHash(digest, rsaSig, hash, RSASignaturePadding.Pkcs1);
    }

    private static bool IsRsaName(string name)
        => name is "ssh-rsa" or "rsa-sha2-256" or "rsa-sha2-512";

    private static HashAlgorithmName RsaHash(SshHostKeyType type) => type switch
    {
        SshHostKeyType.SshRsa => HashAlgorithmName.SHA1,
        SshHostKeyType.RsaSha256 => HashAlgorithmName.SHA256,
        SshHostKeyType.RsaSha512 => HashAlgorithmName.SHA512,
        _ => throw new ArgumentOutOfRangeException(nameof(type)),
    };

    // ════════════════════════════════════════════════════════════════════════
    // ECDSA: ecdsa-sha2-nistp256/384/521
    // ════════════════════════════════════════════════════════════════════════

    private static bool VerifyEcdsa(byte[] hostKey, byte[] exchangeHash, byte[] sigBlob, SshHostKeyType type)
    {
        if (!TryReadSigBody(sigBlob, type, out byte[] body))
        {
            return false;
        }

        // The sig body is itself: string r + string s (hostkey.c:957-961). r/s are
        // big-endian unsigned integers; the backend DER-reconstructs an ECDSA_SIG and
        // verifies (openssl.c:904 _libssh2_ecdsa_verify via i2d_ECDSA_SIG).
        var br = new PacketWireReader(new ReadOnlySequence<byte>(body));
        byte[] r = br.ReadBlob();
        byte[] s = br.ReadBlob();
        byte[] der = EncodeEcdsaDerSig(r, s);

        // K_S = string "ecdsa-sha2-nistpXXX"(19) + string "nistpXXX"(8) + string <SEC1 point>.
        // The domain string ("nistpXXX") selects the curve; libssh2 cross-checks it
        // matches the type (hostkey.c:830-841).
        (ECCurve curve, HashAlgorithmName hash, string domain, int coordSize) = EcdsaParams(type);
        var ks = new PacketWireReader(new ReadOnlySequence<byte>(hostKey));
        if (ks.ReadString() != SigWireName(type))
        {
            return false;
        }

        if (ks.ReadString() != domain)
        {
            return false;
        }

        byte[] point = ks.ReadBlob();
        if (!TryParseSec1Point(point, coordSize, out ECPoint q))
        {
            return false;
        }

        // _libssh2_ecdsa_verify hashes m (=H) with the curve's SHA then verifies the
        // DER signature. BCL ECDsa's 2-arg VerifyHash is platform-dependent (P1363 on
        // Linux, DER historically elsewhere), so use the explicit format overload with
        // the DER (Rfc3279DerSequence) we built — matching OpenSSL's native ECDSA_do_verify.
        byte[] digest = HashData(hash, exchangeHash);
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportParameters(new ECParameters { Curve = curve, Q = q });
        return ecdsa.VerifyHash(digest, der, DSASignatureFormat.Rfc3279DerSequence);
    }

    private static (ECCurve Curve, HashAlgorithmName Hash, string Domain, int CoordSize) EcdsaParams(SshHostKeyType type)
        => type switch
        {
            SshHostKeyType.Ecdsa256 => (ECCurve.NamedCurves.nistP256, HashAlgorithmName.SHA256, "nistp256", 32),
            SshHostKeyType.Ecdsa384 => (ECCurve.NamedCurves.nistP384, HashAlgorithmName.SHA384, "nistp384", 48),
            SshHostKeyType.Ecdsa521 => (ECCurve.NamedCurves.nistP521, HashAlgorithmName.SHA512, "nistp521", 66),
            _ => throw new ArgumentOutOfRangeException(nameof(type)),
        };

    // ════════════════════════════════════════════════════════════════════════
    // Ed25519: ssh-ed25519
    // ════════════════════════════════════════════════════════════════════════

    private static bool VerifyEd25519(byte[] hostKey, byte[] exchangeHash, byte[] sigBlob)
    {
        if (!TryReadSigBody(sigBlob, SshHostKeyType.Ed25519, out byte[] edSig)
            || edSig.Length != Ed25519SigLen)
        {
            // hostkey.c:1269 rejects any sig that isn't exactly LIBSSH2_ED25519_SIG_LEN.
            return false;
        }

        // K_S = string "ssh-ed25519"(11) + string <32-byte pubkey>.
        var ks = new PacketWireReader(new ReadOnlySequence<byte>(hostKey));
        if (ks.ReadString() != "ssh-ed25519")
        {
            return false;
        }

        byte[] pub = ks.ReadBlob();
        if (pub.Length != Ed25519PubkeyLen)
        {
            return false;
        }

        // _libssh2_ed25519_verify verifies over the raw message m (=H); Ed25519's
        // internal SHA-512 applies. Our in-port Ed25519.Verify is the line-for-line
        // RFC 8032 §6 reference.
        return Ed25519.Verify(pub, exchangeHash, edSig);
    }

    // ════════════════════════════════════════════════════════════════════════
    // Shared wire helpers
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Parses the uniform sig-blob envelope <c>string &lt;name&gt; + string &lt;body&gt;</c>,
    /// validates the embedded name against the negotiated <paramref name="type"/>,
    /// and returns the sig body. Returns false on truncation or name mismatch.
    /// </summary>
    private static bool TryReadSigBody(byte[] sigBlob, SshHostKeyType type, out byte[] body)
    {
        body = Array.Empty<byte>();
        var r = new PacketWireReader(new ReadOnlySequence<byte>(sigBlob));
        if (r.ReadString() != SigWireName(type))
        {
            return false;
        }

        body = r.ReadBlob();
        return true;
    }

    /// <summary>
    /// The expected sig-blob type string for a negotiated host-key type.
    /// Delegates to <see cref="SshHostKeyTypeRegistry.WireNameFor(SshHostKeyType)"/>; throws for
    /// non-negotiable types (<see cref="SshHostKeyType.Rsa1"/> /
    /// <see cref="SshHostKeyType.SshDss"/> / <see cref="SshHostKeyType.Unknown"/>),
    /// which never reach the verify path.
    /// </summary>
    private static string SigWireName(SshHostKeyType type)
        => SshHostKeyTypeRegistry.WireNameFor(type)
            ?? throw new ArgumentOutOfRangeException(
                nameof(type),
                $"{type} has no SSH2 sig-blob wire name.");

    /// <summary>
    /// One-shot hash. Switches on the known names to the static
    /// <c>SHA*.HashData</c> (AOT-clean, allocation-light). Mirrors the SHA choice
    /// in <c>_libssh2_rsa_sha2_verify</c> / <c>_libssh2_ecdsa_verify</c>.
    /// </summary>
    [SuppressMessage("Security", "CA5350:Do not use insecure cryptographic algorithms", Justification = "ssh-rsa (SHA-1) is a deprecated-but-supported host-key algorithm kept for parity with libssh2 (LIBSSH2_RSA_SHA1); OpenSSH 8.2+ disables it by default. The SHA1 use here is hostkey-signature verification only.")]
    private static byte[] HashData(HashAlgorithmName name, byte[] data)
    {
        if (name == HashAlgorithmName.SHA1)
        {
            // ssh-rsa (SHA-1) is a deprecated-but-supported host-key algorithm kept
            // for parity with libssh2 (LIBSSH2_RSA_SHA1); OpenSSH 8.2+ disables it by
            // default. The SHA1 use here is hostkey-signature verification only.
            return SHA1.HashData(data);
        }

        if (name == HashAlgorithmName.SHA256)
        {
            return SHA256.HashData(data);
        }

        if (name == HashAlgorithmName.SHA384)
        {
            return SHA384.HashData(data);
        }

        if (name == HashAlgorithmName.SHA512)
        {
            return SHA512.HashData(data);
        }

        throw new ArgumentOutOfRangeException(nameof(name), $"{name} is not a supported hostkey hash.");
    }

    /// <summary>
    /// DER-encodes an ECDSA signature as <c>SEQUENCE { INTEGER r, INTEGER s }</c>
    /// from the SSH wire <c>r</c>/<c>s</c> (big-endian unsigned). Mirrors
    /// <c>BN_bin2bn</c> + <c>i2d_ECDSA_SIG</c> in <c>_libssh2_ecdsa_verify</c>.
    /// Minimal encoding: leading zero bytes stripped; a 0x00 is prepended when the
    /// high bit is set so the INTEGER stays non-negative (X.690 §8.3.2/§8.3.3).
    /// </summary>
    private static byte[] EncodeEcdsaDerSig(byte[] r, byte[] s)
    {
        byte[] rDer = EncodeDerInteger(r);
        byte[] sDer = EncodeDerInteger(s);
        int seqLen = rDer.Length + sDer.Length;
        // Encode the SEQUENCE length (DER definite-length form). ECDSA sigs are at
        // most ~138B (P-521: two 66-byte ints), so seqLen fits in one byte for
        // P-256/P-384 but needs the 0x81 long form once it exceeds 127.
        byte[] lenBytes = seqLen <= 0x7F
            ? new byte[] { (byte)seqLen }
            : new byte[] { 0x81, (byte)seqLen };
        byte[] sig = new byte[1 + lenBytes.Length + seqLen];
        sig[0] = 0x30;  // SEQUENCE
        lenBytes.CopyTo(sig, 1);
        int offset = 1 + lenBytes.Length;
        rDer.CopyTo(sig, offset);
        sDer.CopyTo(sig, offset + rDer.Length);
        return sig;
    }

    /// <summary>Encodes a positive integer as a DER INTEGER (tag 0x02).</summary>
    private static byte[] EncodeDerInteger(byte[] unsignedBE)
    {
        // Strip insignificant leading zero bytes (kept positive regardless).
        int start = 0;
        while (start < unsignedBE.Length - 1 && unsignedBE[start] == 0)
        {
            start++;
        }

        int contentLen = unsignedBE.Length - start;
        bool prependZero = (unsignedBE[start] & 0x80) != 0;
        int len = contentLen + (prependZero ? 1 : 0);

        // contentLen < 128 always for these curve orders → one-byte length form.
        byte[] der = new byte[2 + len];
        der[0] = 0x02;  // INTEGER
        der[1] = (byte)len;
        int offset = 2;
        if (prependZero)
        {
            der[offset] = 0;
            offset++;
        }

        unsignedBE.AsSpan(start, contentLen).CopyTo(der.AsSpan(offset));
        return der;
    }

    /// <summary>
    /// Parses a SEC1 uncompressed point (<c>0x04 ‖ X ‖ Y</c>) into an
    /// <see cref="ECPoint"/> for BCL import. Validates the marker and the
    /// coordinate lengths against the curve's field size. Mirrors the SEC1 parse
    /// in <c>EcdhNistP</c> (transport/EcdhNistP.cs).
    /// </summary>
    private static bool TryParseSec1Point(byte[] point, int coordSize, out ECPoint q)
    {
        q = default;
        if (point.Length != 1 + (2 * coordSize) || point[0] != 0x04)
        {
            return false;
        }

        q = new ECPoint
        {
            X = point.AsSpan(1, coordSize).ToArray(),
            Y = point.AsSpan(1 + coordSize, coordSize).ToArray(),
        };
        return true;
    }
}
