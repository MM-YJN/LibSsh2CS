using System.Security.Cryptography;
using System.Text;

namespace LibSsh2CS;

/// <summary>
/// A parsed OpenSSH private key's type-specific material. The caller
/// (<c>UserAuth.AuthenticateWithPublicKeyAsync</c>) uses this to sign the
/// userauth request via <c>SshSign.Sign</c>. Built by <see cref="Parse"/>
/// from the <see cref="OpenSshKey.PrivateKeyBlob"/> produced by
/// <see cref="SshPemParser"/>.
/// </summary>
/// <remarks>
/// <para>
/// The OpenSSH new-format private key blob (after the PEM armor + bcrypt
/// decryption + check1/check2 validation) is:
/// <code>
/// uint32 check1 | uint32 check2 | string keytype | &lt;type-specific fields&gt; |
/// string comment | byte[] padding (1,2,3,...)
/// </code>
/// <see cref="SshPemParser"/> returns the blob starting at <c>check1</c>; this type
/// re-reads past <c>check1</c>/<c>check2</c>/<c>keytype</c> and extracts the
/// type-specific fields. Mirrors <c>gen_publickey_from_*_openssh_priv_data</c>
/// in <c>openssl.c</c> (RSA at line 1475, ECDSA at line 3578, Ed25519 at 2239).
/// </para>
/// <para>
/// <b>RSA layout</b> (<c>openssl.c:1493-1534</c>): <c>bignum n, bignum e,
/// bignum d, bignum coeff (iqmp), bignum p, bignum q, string comment</c>.
/// Note the order: n, e, d, coeff, p, q — <c>dp</c>/<c>dq</c> are NOT stored by
/// OpenSSH; they are recomputed from <c>d mod (p-1)</c> / <c>d mod (q-1)</c>.
/// <c>coeff</c> is <c>q^-1 mod p</c> (the CRT coefficient).
/// </para>
/// <para>
/// <b>ECDSA layout</b> (<c>openssl.c:3605-3622</c>): <c>string curve,
/// string point (SEC1 uncompressed 0x04‖X‖Y), bignum exponent (private scalar),
/// string comment</c>.
/// </para>
/// <para>
/// <b>Ed25519 layout</b> (<c>openssl.c:2259-2286</c>): <c>string pub_key (32
/// bytes), string priv_key (64 bytes = 32-byte seed ‖ 32-byte pub copy),
/// string comment</c>. The Ed25519 RFC 8032 private-key seed is the first 32
/// bytes of <c>priv_key</c>.
/// </para>
/// </remarks>
public abstract record SshPemKey
{
    /// <summary>The key type (Rsa / Ecdsa / Ed25519). Determines the
    /// <c>SshSign.Sign</c> dispatch path.</summary>
    public abstract SshKeyType KeyType { get; }

    /// <summary>
    /// Parses the type-specific fields from <paramref name="openSshKey"/>'s
    /// <see cref="OpenSshKey.PrivateKeyBlob"/> (which starts at
    /// <c>check1</c>). Re-reads past <c>check1</c>/<c>check2</c>/<c>keytype</c>
    /// and dispatches on the keytype string. Returns a concrete
    /// <see cref="RsaPemKey"/>, <see cref="SshEcdsaPemKey"/>, or
    /// <see cref="SshEd25519PemKey"/>.
    /// </summary>
    /// <exception cref="SshException">Thrown with
    /// <see cref="SshErrorCode.Proto"/> on a malformed blob or an unrecognized
    /// keytype, or <see cref="SshErrorCode.OutOfBoundary"/> on truncation.</exception>
    public static SshPemKey Parse(OpenSshKey openSshKey)
    {
        ArgumentNullException.ThrowIfNull(openSshKey);

        // The PrivateKeyBlob starts at check1. Re-read: check1 (u32), check2 (u32),
        // keytype (string), then the type-specific fields.
        var r = new SshWireReader(openSshKey.PrivateKeyBlob);
        _ = r.ReadUInt32(); // check1 — already validated by PemParser
        _ = r.ReadUInt32(); // check2 — already validated by PemParser
        ReadOnlySpan<byte> keytype = r.ReadSshBytes();

        if (keytype.SequenceEqual("ssh-rsa"u8))
        {
            return ParseRsa(r);
        }
        if (keytype.SequenceEqual("ecdsa-sha2-nistp256"u8))
        {
            return ParseEcdsa(r, ECCurve.NamedCurves.nistP256, "nistp256");
        }
        if (keytype.SequenceEqual("ecdsa-sha2-nistp384"u8))
        {
            return ParseEcdsa(r, ECCurve.NamedCurves.nistP384, "nistp384");
        }
        if (keytype.SequenceEqual("ecdsa-sha2-nistp521"u8))
        {
            return ParseEcdsa(r, ECCurve.NamedCurves.nistP521, "nistp521");
        }
        if (keytype.SequenceEqual("ssh-ed25519"u8))
        {
            return ParseEd25519(r);
        }

        throw new SshException(SshErrorCode.Proto, $"Unsupported keytype: {Encoding.ASCII.GetString(keytype)}");
    }

    // ════════════════════════════════════════════════════════════════════════
    // RSA: ssh-rsa
    // ════════════════════════════════════════════════════════════════════════

    private static RsaPemKey ParseRsa(SshWireReader r)
    {
        // openssl.c:1493-1534. Order: n, e, d, coeff, p, q, comment.
        byte[] n = r.ReadSshBytes().ToArray();
        byte[] e = r.ReadSshBytes().ToArray();
        byte[] d = r.ReadSshBytes().ToArray();
        byte[] coeff = r.ReadSshBytes().ToArray();
        byte[] p = r.ReadSshBytes().ToArray();
        byte[] q = r.ReadSshBytes().ToArray();
        // The comment string follows and is REQUIRED: the C reads it
        // and fails hard when it cannot (openssl.c:1524, PROTO "RSA no
        // comment") — the structural read is the C's format validation. The
        // value is not surfaced (PemParser's OpenSshKey.Comment is empty by
        // design).
        _ = r.ReadSshBytes();   // comment (required; not surfaced)
        return new RsaPemKey(n, e, d, coeff, p, q);
    }

    // ════════════════════════════════════════════════════════════════════════
    // ECDSA: ecdsa-sha2-nistp256/384/521
    // ════════════════════════════════════════════════════════════════════════

    private static SshEcdsaPemKey ParseEcdsa(SshWireReader r, ECCurve curve, string curveName)
    {
        // openssl.c:3605-3622. Order: curve, point, exponent, comment.
        ReadOnlySpan<byte> curveWire = r.ReadSshBytes();
        if (!Ascii.Equals(curveWire, curveName))
        {
            throw new SshException(SshErrorCode.Proto,
                $"ECDSA curve mismatch: keytype says {curveName}, blob says {Encoding.ASCII.GetString(curveWire)}");
        }

        byte[] point = r.ReadSshBytes().ToArray();        // SEC1 uncompressed: 0x04 ‖ X ‖ Y
        byte[] exponent = r.ReadSshBytes().ToArray();      // private scalar (big-endian)
        return new SshEcdsaPemKey(curve, curveName, point, exponent);
    }

    // ════════════════════════════════════════════════════════════════════════
    // Ed25519: ssh-ed25519
    // ════════════════════════════════════════════════════════════════════════

    private static SshEd25519PemKey ParseEd25519(SshWireReader r)
    {
        // openssl.c:2259-2286. Order: pub_key (32B), priv_key (64B = seed‖pub), comment.
        ReadOnlySpan<byte> pubKey = r.ReadSshBytes();
        if (pubKey.Length != 32)
        {
            throw new SshException(SshErrorCode.Proto,
                $"Ed25519 public key must be 32 bytes, got {pubKey.Length}");
        }

        ReadOnlySpan<byte> privKey = r.ReadSshBytes();
        if (privKey.Length != 64)
        {
            throw new SshException(SshErrorCode.Proto,
                $"Ed25519 private key blob must be 64 bytes, got {privKey.Length}");
        }

        // The first 32 bytes of priv_key are the RFC 8032 private-key seed.
        byte[] seed = privKey.Slice(0, 32).ToArray();

        // Comment string follows and is REQUIRED: the C fails hard when
        // it cannot read it (openssl.c:2281-2286, PROTO "Unable to read
        // comment") — a truncated/missing comment is NOT "absent", and the
        // port previously swallowed the read failure and accepted comment-less
        // blobs whose (empty) tail trivially passed the padding check. The
        // port surfaces the truncation as OutOfBoundary (its established error
        // for these structural reads; the C's PROTO is not re-mapped). The
        // padding tail after the comment is then validated: the remaining
        // bytes must be the sequence 1, 2, 3, … (openssl.c:2301-2312 — any
        // deviation is PROTO "Wrong padding").
        _ = r.ReadSshBytes();   // comment (not surfaced by the port)

        ReadOnlySpan<byte> tail = r.RemainingBytes;
        for (int i = 0; i < tail.Length; i++)
        {
            if (tail[i] != i + 1)
            {
                throw new SshException(SshErrorCode.Proto, "Wrong padding");
            }
        }

        return new SshEd25519PemKey(seed, pubKey.ToArray());
    }
}
