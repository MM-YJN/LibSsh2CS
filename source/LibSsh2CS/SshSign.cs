using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

using LibSsh2CS.Crypto;
using LibSsh2CS.Util;

namespace LibSsh2CS;

/// <summary>
/// Signs the SSH userauth data blob (<c>session_id ‖ USERAUTH_REQUEST</c>)
/// with a parsed private key, producing the SSH signature blob
/// (<c>[string algoName][string rawSig]</c>) that the publickey / hostbased
/// auth flows append to the USERAUTH_REQUEST. Dispatches on the key type to the
/// RSA / ECDSA / Ed25519 backend. Replaces libssh2's
/// <c>hostkey_method_*_signv</c> + <c>_libssh2_*_sign</c> path.
/// </summary>
/// <remarks>
/// <para>
/// <b>Signs the precomputed hash, not the raw data — for RSA/ECDSA.</b>
/// libssh2's <c>hostkey_method_*_signv</c> (<c>hostkey.c:230-265</c>,
/// <c>hostkey.c:304-343</c>) hash the datavec (<c>session_id ‖
/// USERAUTH_REQUEST</c>) with the algorithm's hash, then pass the digest to
/// <c>_libssh2_rsa_sha2_sign</c> / <c>_libssh2_ecdsa_sign</c>, which sign the
/// digest. The BCL <c>RSA.SignHash</c> / <c>ECDsa.SignHash</c> mirror this.
/// Ed25519 is different: <c>_libssh2_ed25519_sign</c> signs the raw message
/// (Ed25519 does its own internal SHA-512), so <c>Ed25519.Sign(seed, data)</c>
/// takes the raw data.
/// </para>
/// <para>
/// <b>Signature blob wire format</b> (<c>userauth.c:1823-1828</c>, non-SK
/// branch): <c>[string algoName][string rawSig]</c>, where <c>rawSig</c> is:
/// <list type="bullet">
/// <item>RSA: the PKCS#1 v1.5 signature bytes (length = modulus length).</item>
/// <item>ECDSA: <c>[string r][string s]</c> — r and s as big-endian unsigned
/// integers, each length-prefixed.</item>
/// <item>Ed25519: the 64-byte <c>R ‖ S</c>.</item>
/// </list>
/// </para>
/// <para>
/// <b>RSA-SHA2 algorithm selection</b> (RFC 8332): <c>ssh-rsa</c> signs with
/// SHA-1, <c>rsa-sha2-256</c> with SHA-256, <c>rsa-sha2-512</c> with SHA-512.
/// The caller (<c>UserAuth</c>) picks the algorithm name from
/// <c>server-sig-algs</c> (parity with <c>userauth.c:1351</c>
/// <c>_libssh2_key_sign_algorithm</c>) and passes it here; this type's
/// <see cref="Sign"/> switches on it for the hash.
/// </para>
/// </remarks>
internal static class SshSign
{
    /// <summary>
    /// Signs <paramref name="data"/> with <paramref name="key"/> using the
    /// algorithm <paramref name="algoName"/>, returning the SSH signature blob
    /// (<c>[string algoName][string rawSig]</c>).
    /// </summary>
    /// <param name="key">The parsed private key.</param>
    /// <param name="data">The raw data to sign (the <c>session_id ‖
    /// USERAUTH_REQUEST</c> buffer built by <c>UserAuth</c>).</param>
    /// <param name="algoName">The signing algorithm name — must be a valid
    /// publickey algorithm for the key type: <c>ssh-rsa</c> /
    /// <c>rsa-sha2-256</c> / <c>rsa-sha2-512</c> for RSA,
    /// <c>ecdsa-sha2-nistp256</c> / <c>ecdsa-sha2-nistp384</c> /
    /// <c>ecdsa-sha2-nistp521</c> for ECDSA, <c>ssh-ed25519</c> for Ed25519.
    /// For RSA the name selects the hash (SHA-1/256/512); for ECDSA/Ed25519 it
    /// must match the key's curve/type.</param>
    /// <returns>The SSH signature blob: <c>[string algoName][string rawSig]
    /// </c> — ready to append to the USERAUTH_REQUEST packet.</returns>
    /// <exception cref="SshException">Thrown with
    /// <see cref="SshErrorCode.PublicKeyProtocol"/> if <paramref name="algoName"/>
    /// is not valid for the key type.</exception>
    public static byte[] Sign(SshPemKey key, byte[] data, string algoName)
    {
        return key switch
        {
            RsaPemKey rsa => SignRsa(rsa, data, algoName),
            SshEcdsaPemKey ecdsa => SignEcdsa(ecdsa, data, algoName),
            SshEd25519PemKey ed => SignEd25519(ed, data, algoName),
            _ => throw new SshException(SshErrorCode.PublicKeyProtocol,
                $"Unknown key type: {key.GetType()}"),
        };
    }

    // ════════════════════════════════════════════════════════════════════════
    // RSA: ssh-rsa (SHA-1) / rsa-sha2-256 / rsa-sha2-512
    // ════════════════════════════════════════════════════════════════════════

    [SuppressMessage("Security", "CA5350:Do not use insecure cryptographic algorithms", Justification = "SHA-1 use is for ssh-rsa parity (OpenSSH 8.2+ disables by default)")]
    private static byte[] SignRsa(RsaPemKey key, byte[] data, string algoName)
    {
        // hostkey.c:242-265 (SHA-1) / 319-342 (SHA-256) / 405-428 (SHA-512):
        // hash the data with the algorithm's hash, then _libssh2_rsa_sha2_sign
        // signs the digest with PKCS#1 v1.5. BCL RSA.SignHash mirrors this
        // exactly (the DigestInfo wrapping is part of SignHash).
        HashAlgorithmName hash = algoName switch
        {
            "ssh-rsa" => HashAlgorithmName.SHA1,
            "rsa-sha2-256" => HashAlgorithmName.SHA256,
            "rsa-sha2-512" => HashAlgorithmName.SHA512,
            _ => throw new SshException(SshErrorCode.PublicKeyProtocol,
                $"Unsupported RSA signing algorithm: {algoName}"),
        };

        byte[] digest = HashData(hash, data);

        // BCrypt (Windows) derives the key bit length from Modulus.Length and
        // mandates fixed-width fields: D == cbModulus, P/Q/DP/DQ/InverseQ ==
        // ceil(cbModulus / 2). OpenSSL (Linux) silently tolerates both the
        // SSH mpint 0x00 sign guard (added whenever a field's high bit is set,
        // so n/d/p/q/coeff can be fieldLen+1 bytes here) and shorter-than-
        // field minimal encodings. Two problems follow on Windows:
        //  (1) A sign-guarded Modulus makes BCrypt compute the wrong cbPrime
        //      (e.g. 129 instead of 128 for a 2048-bit key whose n has its
        //      high bit set) and SignHash later fails with "cryptographic
        //      operation". Strip the leading zero(s) so BCrypt sees the
        //      canonical key size.
        //  (2) DeriveCrt below returns a minimal BigInteger encoding (so
        //      dp/dq can be shorter than primeLen when their high bits are
        //      clear); BCrypt rejects these. Left-pad (or strip a leading
        //      zero guard) every other field to the resulting widths.
        byte[] modulus = StripLeadingZeros(key.Modulus);
        int primeLen = (modulus.Length + 1) / 2;

        using var rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters
        {
            Modulus = modulus,
            Exponent = key.PublicExponent,
            D = LeftPadToLength(key.PrivateExponent, modulus.Length),
            P = LeftPadToLength(key.PrimeP, primeLen),
            Q = LeftPadToLength(key.PrimeQ, primeLen),
            DP = LeftPadToLength(DeriveCrt(key.PrivateExponent, key.PrimeP), primeLen),
            DQ = LeftPadToLength(DeriveCrt(key.PrivateExponent, key.PrimeQ), primeLen),
            InverseQ = LeftPadToLength(key.Coefficient, primeLen),
        });

        byte[] sig;
        sig = rsa.SignHash(digest, hash, RSASignaturePadding.Pkcs1);

        return BuildSshSigBlob(algoName, sig);
    }

    // ════════════════════════════════════════════════════════════════════════
    // ECDSA: ecdsa-sha2-nistp256/384/521
    // ════════════════════════════════════════════════════════════════════════

    private static byte[] SignEcdsa(SshEcdsaPemKey key, byte[] data, string algoName)
    {
        // hostkey.c:968-991: hash with the curve's SHA, _libssh2_ecdsa_sign
        // signs the digest. BCL ECDsa.SignHash returns a DER SEQUENCE {r, s}
        // (the same form OpenSSL's ECDSA_do_sign produces); we then re-encode
        // it into the SSH wire form [string r][string s] for the sig blob.
        (HashAlgorithmName hash, int coordSize) = algoName switch
        {
            "ecdsa-sha2-nistp256" => (HashAlgorithmName.SHA256, 32),
            "ecdsa-sha2-nistp384" => (HashAlgorithmName.SHA384, 48),
            "ecdsa-sha2-nistp521" => (HashAlgorithmName.SHA512, 66),
            _ => throw new SshException(SshErrorCode.PublicKeyProtocol,
                $"Unsupported ECDSA signing algorithm: {algoName}"),
        };

        // Cross-check the algo matches the key's curve (defensive — the caller
        // should have derived algoName from the key, but a mismatch would
        // produce a signature the server can't verify).
        bool curveMatches = algoName switch
        {
            "ecdsa-sha2-nistp256" => string.Equals(key.CurveName, "nistp256", StringComparison.Ordinal),
            "ecdsa-sha2-nistp384" => string.Equals(key.CurveName, "nistp384", StringComparison.Ordinal),
            "ecdsa-sha2-nistp521" => string.Equals(key.CurveName, "nistp521", StringComparison.Ordinal),
            _ => false,
        };
        if (!curveMatches)
        {
            throw new SshException(SshErrorCode.PublicKeyProtocol,
                $"ECDSA algo {algoName} does not match key curve {key.CurveName}");
        }

        byte[] digest = HashData(hash, data);

        // Import the private scalar. BCL ECDsa.ImportParameters wants D as the
        // private scalar (big-endian) and mandates its length equal the curve's
        // field/order size (coordSize). The key's Exponent comes from the SSH
        // mpint in the OpenSSH blob, which may carry a 0x00 sign guard (making
        // it coordSize+1 when the scalar's high bit is set) or be shorter than
        // coordSize (minimal encoding when the high bits are clear). OpenSSL's
        // BN_bin2bn + EC_KEY_set_private_key silently tolerate both because
        // BIGNUM is an arbitrary-precision integer, not a fixed-width field;
        // the BCL is stricter. Normalize to coordSize: strip leading 0x00
        // (StripLeadingZeros) then left-pad (LeftPadToLength) — the same
        // normalization the RSA path below applies to d/p/q for BCrypt. This
        // mirrors BN_bin2bn's effective semantics, not an algorithm change.
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportParameters(new ECParameters
        {
            Curve = key.Curve,
            Q = ParseSec1Point(key.Point, coordSize),
            D = LeftPadToLength(StripLeadingZeros(key.Exponent), coordSize),
        });

        // SignHash returns DER (Rfc3279DerSequence) — the same format the verify
        // path requests in HostKeyVerifier. We then parse it back into r/s for
        // the SSH wire blob. The 2-arg SignHash is platform-dependent; the
        // explicit-format overload is deterministic.
        byte[] derSig = ecdsa.SignHash(digest, DSASignatureFormat.Rfc3279DerSequence);
        (byte[] r, byte[] s) = ParseEcdsaDerSig(derSig);
        byte[] rawSig = BuildEcdsaSshSigBody(r, s);
        return BuildSshSigBlob(algoName, rawSig);
    }

    // ════════════════════════════════════════════════════════════════════════
    // Ed25519: ssh-ed25519
    // ════════════════════════════════════════════════════════════════════════

    private static byte[] SignEd25519(SshEd25519PemKey key, byte[] data, string algoName)
    {
        if (algoName != "ssh-ed25519")
        {
            throw new SshException(SshErrorCode.PublicKeyProtocol,
                $"Unsupported Ed25519 signing algorithm: {algoName}");
        }

        // _libssh2_ed25519_sign signs the raw message (Ed25519 does its own
        // SHA-512 internally). Our Ed25519.Sign is the RFC 8032 §5.1.5 port.
        byte[] sig = Ed25519.Sign(key.Seed, data);
        return BuildSshSigBlob("ssh-ed25519", sig);
    }

    // ════════════════════════════════════════════════════════════════════════
    // Shared helpers
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Builds the SSH signature blob: <c>[string algoName][string rawSig]</c>.
    /// Port of <c>userauth.c:1823-1828</c>'s non-SK branch.
    /// </summary>
    internal static byte[] BuildSshSigBlob(string algoName, byte[] rawSig)
    {
        byte[] nameBytes = System.Text.Encoding.UTF8.GetBytes(algoName);
        byte[] blob = new byte[4 + nameBytes.Length + 4 + rawSig.Length];
        BinaryPrimitives.WriteInt32BigEndian(blob.AsSpan(0, 4), nameBytes.Length);
        nameBytes.CopyTo(blob, 4);
        BinaryPrimitives.WriteInt32BigEndian(blob.AsSpan(4 + nameBytes.Length, 4), rawSig.Length);
        rawSig.CopyTo(blob, 8 + nameBytes.Length);
        return blob;
    }

    /// <summary>
    /// Builds the ECDSA raw signature body <c>[string r][string s]</c> from the
    /// big-endian r and s. Mirrors the SSH wire form the verify path parses
    /// (<c>HostKeyVerifier.cs:159-161</c>).
    /// </summary>
    private static byte[] BuildEcdsaSshSigBody(byte[] r, byte[] s)
    {
        byte[] blob = new byte[4 + r.Length + 4 + s.Length];
        BinaryPrimitives.WriteInt32BigEndian(blob.AsSpan(0, 4), r.Length);
        r.CopyTo(blob, 4);
        BinaryPrimitives.WriteInt32BigEndian(blob.AsSpan(4 + r.Length, 4), s.Length);
        s.CopyTo(blob, 8 + r.Length);
        return blob;
    }

    /// <summary>
    /// Parses a DER <c>SEQUENCE { INTEGER r, INTEGER s }</c> into the raw r and
    /// s byte arrays (big-endian unsigned). The inverse of
    /// <c>HostKeyVerifier.EncodeEcdsaDerSig</c>.
    /// </summary>
    private static (byte[] R, byte[] S) ParseEcdsaDerSig(byte[] der)
    {
        // Minimal DER parser: SEQUENCE { INTEGER, INTEGER }.
        if (der.Length < 2 || der[0] != 0x30)
        {
            throw new SshException(SshErrorCode.Proto, "ECDSA sig is not a DER SEQUENCE");
        }

        int offset = 1;
        int lenByte = der[offset++];
        if ((lenByte & 0x80) != 0)
        {
            // Long-form length (0x81 prefix) — one extra byte. The actual
            // length value is not needed; the parser is purely position-based
            // (the two INTEGERs are read sequentially from the SEQUENCE body).
            int lenBytes = lenByte & 0x7F;
            if (lenBytes != 1)
            {
                throw new SshException(SshErrorCode.Proto,
                    $"ECDSA sig unexpected DER length form: {lenBytes} bytes");
            }

            offset++;   // consume the one length byte
        }

        byte[] r = ReadDerInteger(der, ref offset);
        byte[] s = ReadDerInteger(der, ref offset);
        return (r, s);
    }

    /// <summary>Reads one DER INTEGER (tag 0x02) and returns the BE value in
    /// the SSH <c>bignum2</c> wire form that <c>write_bn</c>
    /// (<c>openssl.c:222-237</c>) produces: the 0x00 sign guard is <b>retained</b>
    /// when the value's high bit is set (the guard is part of the wire bytes,
    /// not stripped), matching what OpenSSH's <c>sshbuf_put_bignum2</c> writes
    /// and what the server's verify path re-parses. Stripping the guard (as a
    /// naïve unsigned-BE conversion would) produces a shorter r/s that
    /// OpenSSH misinterprets as negative under the <c>bignum2</c> signed
    /// convention, failing signature verification.</summary>
    private static byte[] ReadDerInteger(byte[] der, ref int offset)
    {
        if (der[offset] != 0x02)
        {
            throw new SshException(SshErrorCode.Proto, "ECDSA sig expected DER INTEGER");
        }

        offset++;
        int len = der[offset++];
        byte[] value = new byte[len];
        Buffer.BlockCopy(der, offset, value, 0, len);
        offset += len;

        // The DER INTEGER content is already in the form write_bn emits:
        // a 0x00 sign guard is present iff the value's high bit is set. Keep
        // it verbatim — do not strip. (DER and SSH bignum2 agree on the guard
        // here; the only difference is the length-prefix encoding, which
        // BuildEcdsaSshSigBody adds.)
        return value;
    }

    /// <summary>
    /// Computes <c>d mod (p-1)</c> (the CRT exponent dp) from the stored d and
    /// p. OpenSSH does not store dp/dq; OpenSSL recomputes them
    /// (<c>_libssh2_rsa_new_additional_parameters</c>, <c>openssl.c:1553</c>).
    /// </summary>
    private static byte[] DeriveCrt(byte[] d, byte[] p)
    {
        System.Numerics.BigInteger dBi = Endian.BigIntegerFromBigEndian(d);
        System.Numerics.BigInteger pBi = Endian.BigIntegerFromBigEndian(p);
        System.Numerics.BigInteger dp = dBi % (pBi - System.Numerics.BigInteger.One);
        return Endian.BigIntegerToBigEndianBytes(dp);
    }

    /// <summary>
    /// Returns <paramref name="value"/> with all leading 0x00 bytes removed
    /// (but always preserving at least one byte). For RSA fields parsed from
    /// the SSH mpint wire format this strips the 0x00 sign guard that gets
    /// added when the field's high bit is set. The minimal encoding of any
    /// positive integer starts with a non-zero byte, so this is value-preserving.
    /// </summary>
    private static byte[] StripLeadingZeros(byte[] value)
    {
        int i = 0;
        while (i < value.Length - 1 && value[i] == 0)
        {
            i++;
        }

        return i == 0 ? value : value.AsSpan(i).ToArray();
    }

    /// <summary>
    /// Returns <paramref name="value"/> re-encoded to exactly
    /// <paramref name="length"/> bytes (big-endian). Strips a leading 0x00
    /// SSH-mpint sign guard when present; left-pads with zero bytes when the
    /// value's minimal encoding is shorter (e.g. a <see cref="DeriveCrt"/>
    /// result whose high bits are clear). Throws if a longer-than-target value
    /// has a non-zero leading byte (the value genuinely overflows the field —
    /// a malformed key). Required because Windows BCrypt's
    /// <c>BCRYPT_RSAKEY_BLOB</c> mandates fixed-width fields:
    /// <c>cbModulus</c> for <c>D</c>, <c>cbPrime</c> = <c>(cbModulus + 1) / 2</c>
    /// for <c>P</c>/<c>Q</c>/<c>DP</c>/<c>DQ</c>/<c>InverseQ</c>. OpenSSL
    /// silently re-pads, so without this normalization the same
    /// <see cref="RSAParameters"/> succeeds on Linux and fails on Windows.
    /// Mirrors OpenSSL's internal padding in
    /// <c>openssl.c:_libssh2_rsa_new_additional_parameters</c>.
    /// </summary>
    private static byte[] LeftPadToLength(byte[]? value, int length)
    {
        if (value is null || value.Length == 0)
        {
            return new byte[length];
        }

        if (value.Length == length)
        {
            return value;
        }

        if (value.Length > length)
        {
            // Allowed only if the extra leading bytes are zero (SSH mpint
            // sign guard). Anything else means the value is genuinely too
            // large for a prime of this modulus — the key is malformed.
            int extra = value.Length - length;
            for (int i = 0; i < extra; i++)
            {
                if (value[i] != 0)
                {
                    throw new SshException(SshErrorCode.PublicKeyProtocol,
                        $"RSA CRT parameter is {value.Length} bytes; expected {length}. " +
                        "Leading bytes are non-zero (malformed key).");
                }
            }

            return value.AsSpan(extra).ToArray();
        }

        // value.Length < length — left-pad with zeros.
        byte[] padded = new byte[length];
        Buffer.BlockCopy(value, 0, padded, length - value.Length, value.Length);
        return padded;
    }

    /// <summary>One-shot hash (matches <c>HostKeyVerifier.HashData</c>).</summary>
    [SuppressMessage("Security", "CA5350:Do not use insecure cryptographic algorithms", Justification = "SHA-1 use is for ssh-rsa parity (OpenSSH 8.2+ disables by default)")]
    private static byte[] HashData(HashAlgorithmName name, byte[] data)
    {
        if (name == HashAlgorithmName.SHA1)
        {
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

        throw new ArgumentOutOfRangeException(nameof(name), $"{name} is not a supported hash.");
    }

    /// <summary>
    /// Parses a SEC1 uncompressed point (<c>0x04 ‖ X ‖ Y</c>) into an
    /// <see cref="ECPoint"/>. Mirrors <c>HostKeyVerifier.TryParseSec1Point</c>.
    /// </summary>
    private static ECPoint ParseSec1Point(byte[] point, int coordSize)
    {
        if (point.Length != 1 + (2 * coordSize) || point[0] != 0x04)
        {
            throw new SshException(SshErrorCode.Proto,
                $"ECDSA public point is not a valid SEC1 uncompressed point");
        }

        return new ECPoint
        {
            X = point.AsSpan(1, coordSize).ToArray(),
            Y = point.AsSpan(1 + coordSize, coordSize).ToArray(),
        };
    }
}
