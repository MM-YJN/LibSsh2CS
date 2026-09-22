using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;

using LibSsh2CS.Crypto;
using LibSsh2CS.Transport;
using LibSsh2CS.Util;

namespace LibSsh2CS;

/// <summary>
/// Managed port of <c>pem.c</c> from libssh2 1.11.1_DEV.
/// </summary>
/// <remarks>
/// <para>
/// Parses the OpenSSH new-format private key file
/// (<c>-----BEGIN OPENSSH PRIVATE KEY-----</c> ... <c>-----END OPENSSH PRIVATE KEY-----</c>),
/// including bcrypt-encrypted keys. Mirrors the behavior of libssh2's
/// <c>_libssh2_openssh_pem_parse_memory</c> + <c>_libssh2_openssh_pem_parse_data</c>.
/// </para>
/// <para>
/// <b>Scope:</b>
/// <list type="bullet">
///   <item>OpenSSH new-format private keys, including bcrypt-encrypted keys
///       (what modern <c>ssh-keygen</c> writes by default).</item>
///   <item>Legacy PEM accepted by libssh2 via OpenSSL's
///       <c>PEM_read_bio_PrivateKey</c> (openssl.c:5016): unencrypted and
///       traditional-encrypted (<c>Proc-Type: 4,ENCRYPTED</c> +
///       <c>DEK-Info</c>, EVP_BytesToKey-MD5) PKCS#1 RSA; PKCS#8
///       (<c>-----BEGIN PRIVATE KEY-----</c> unencrypted and
///       <c>-----BEGIN ENCRYPTED PRIVATE KEY-----</c> PBES2-encrypted,
///       PBKDF2 + AES-CBC/DES-EDE3-CBC) with RSA, EC (id-ecPublicKey +
///       namedCurve), and Ed25519 (id-Ed25519) inner keys; SEC1 EC
///       (<c>-----BEGIN EC PRIVATE KEY-----</c>, RFC 5915). DSA/SK legacy
///       PEM and non-PBES2 PKCS#8 encryption remain deferred.</item>
///   <item>Ciphers supported: <c>none</c>, <c>aes256-ctr</c>, <c>aes192-ctr</c>,
///       <c>aes128-ctr</c>, <c>aes256-cbc</c>, <c>aes192-cbc</c>, <c>aes128-cbc</c>,
///       <c>aes256-gcm@openssh.com</c>, <c>aes128-gcm@openssh.com</c>. The GCM
///       AEAD ciphers use the raw 12-byte derived IV as the nonce with no AAD
///       and read the 16-byte auth tag from the trailing bytes of the outer
///       stream (<c>pem.c:645-663</c>); see <see cref="AesGcmKeyFileDecrypt"/>.</item>
///   <item>KDFs supported: <c>none</c>, <c>bcrypt</c> (OpenSSH format);
///       EVP_BytesToKey-MD5 (traditional PEM); PBKDF2-HMAC-SHA1/SHA256
///       (PBES2 PKCS#8).</item>
/// </list>
/// </para>
/// <para>
/// <b>Source:</b> <c>~/repo/libssh2/src/pem.c</c> lines 386–877 (OpenSSH path);
/// legacy PEM/ASN.1 handling follows the behavior of the OpenSSL
/// <c>PEM_read_bio_PrivateKey</c> calls the C makes (openssl.c:5016) —
/// pem_lib.c <c>PEM_ASN1_write_bio</c>/<c>PEM_do_header</c> for the
/// traditional scheme, RFC 5208/8018 for PKCS#8.
/// </para>
/// <para>
/// <b>License:</b> BSD-3-Clause (The Written Word, Inc.; Simon Josefsson).
/// </para>
/// <para>
/// <b>Error-code note:</b> missing/broken armor throws
/// <see cref="SshErrorCode.File"/> — this mirrors the USER-FACING libssh2
/// path, where <c>libssh2_userauth_publickey_frommemory</c> maps the
/// OpenSSH-parse failure to <c>LIBSSH2_ERROR_FILE</c> "Unsupported private
/// key file format" (openssl.c:5043-5047); the internal
/// <c>_libssh2_openssh_pem_parse_memory</c> itself uses
/// <c>LIBSSH2_ERROR_PROTO</c> (pem.c:811-865). Truncated key data throws
/// <see cref="SshErrorCode.Proto"/> (the C's under-read code, pem.c:429-678).
/// </para>
/// <para>
/// <b>Passphrase encoding contract:</b> the passphrase is UTF-8-encoded
/// (pem.c hashes the raw <c>char*</c> bytes the caller supplied — libssh2
/// specifies no encoding, so a C caller passing Latin-1 bytes derives
/// different key material than the C# equivalent for the same characters).
/// </para>
/// </remarks>
public static class SshPemParser
{
    /// <summary>
    /// Cap (divergence — the C is uncapped): the maximum
    /// bcrypt <c>rounds</c> accepted from an openssh-key-v1 KDF options blob
    /// (~2¹⁰ × the OpenSSH default of 16). Rejected with <c>Decrypt</c>
    /// "invalid format" before deriving.
    /// </summary>
    private const uint MaxBcryptRounds = 1 << 20;

    /// <summary>
    /// Cap (divergence — the C is uncapped): the maximum
    /// PBKDF2 <c>iterations</c> accepted from PBES2 parameters. Rejected with
    /// <c>File</c> before deriving.
    /// </summary>
    private const long MaxPbkdf2Iterations = 100_000_000;

    private const string AuthMagic = "openssh-key-v1";

    private static ReadOnlySpan<byte> OpensshHeaderBegin => "-----BEGIN OPENSSH PRIVATE KEY-----"u8;
    private static ReadOnlySpan<byte> OpensshHeaderEnd => "-----END OPENSSH PRIVATE KEY-----"u8;

    // Legacy PEM armor (unencrypted PKCS#1 RSA — what `ssh-keygen -m PEM`
    // emits). Accepted by libssh2 via OpenSSL's PEM_read_bio_PrivateKey
    // (openssl.c:5016).
    private static ReadOnlySpan<byte> RsaPemHeaderBegin => "-----BEGIN RSA PRIVATE KEY-----"u8;
    private static ReadOnlySpan<byte> RsaPemHeaderEnd => "-----END RSA PRIVATE KEY-----"u8;

    // SEC1 EC armor (RFC 5915, what `openssl ecparam -genkey` emits), also
    // accepted by libssh2 via PEM_read_bio_PrivateKey (openssl.c:5016, 5076-5080).
    private static ReadOnlySpan<byte> EcPemHeaderBegin => "-----BEGIN EC PRIVATE KEY-----"u8;
    private static ReadOnlySpan<byte> EcPemHeaderEnd => "-----END EC PRIVATE KEY-----"u8;

    // PKCS#8 armor: unencrypted PrivateKeyInfo ("PRIVATE KEY") and the
    // EncryptedPrivateKeyInfo form ("ENCRYPTED PRIVATE KEY", PBES2/PBKDF2).
    // Also accepted by libssh2 via PEM_read_bio_PrivateKey (openssl.c:5016).
    private static ReadOnlySpan<byte> Pkcs8HeaderBegin => "-----BEGIN PRIVATE KEY-----"u8;
    private static ReadOnlySpan<byte> Pkcs8HeaderEnd => "-----END PRIVATE KEY-----"u8;
    private static ReadOnlySpan<byte> EncryptedPkcs8HeaderBegin => "-----BEGIN ENCRYPTED PRIVATE KEY-----"u8;
    private static ReadOnlySpan<byte> EncryptedPkcs8HeaderEnd => "-----END ENCRYPTED PRIVATE KEY-----"u8;

    /// <summary>
    /// Parses an OpenSSH-format private key from a text file. The input is the
    /// raw file contents (including PEM armor). Equivalent to libssh2's
    /// <c>_libssh2_openssh_pem_parse_memory</c>.
    /// </summary>
    /// <param name="fileContents">The full file bytes (ASCII/UTF-8 with PEM armor).</param>
    /// <param name="passphrase">
    /// The passphrase for encrypted keys, or <see langword="null"/> for unencrypted keys.
    /// </param>
    /// <returns>The parsed key record.</returns>
    /// <exception cref="SshException">
    /// Thrown with appropriate <see cref="SshErrorCode"/> if parsing fails (wrong
    /// format, missing passphrase, wrong passphrase, unsupported cipher).
    /// </exception>
    public static OpenSshKey ParseOpenSshPrivateKey(ReadOnlySpan<byte> fileContents, string? passphrase = null)
    {
        // Strip PEM armor and concatenate base64 lines.
        ReadOnlySpan<byte> b64 = ExtractBase64Body(fileContents, OpensshHeaderBegin, OpensshHeaderEnd);
        if (b64.Length == 0)
        {
            // Legacy PEM armor — the C accepts these via OpenSSL's
            // PEM_read_bio_PrivateKey (openssl.c:5016); previously every
            // legacy key was rejected with File. Handles the unencrypted and traditional-encrypted
            // (Proc-Type: 4,ENCRYPTED + DEK-Info) PKCS#1 form, SEC1 EC,
            // and PKCS#8 (unencrypted PrivateKeyInfo and PBES2-encrypted
            // EncryptedPrivateKeyInfo) with RSA/EC/Ed25519 inner keys.
            // DSA/SK legacy PEM remains deferred.
            ReadOnlySpan<byte> legacyB64 = ExtractBase64Body(fileContents, RsaPemHeaderBegin, RsaPemHeaderEnd);
            if (legacyB64.Length > 0)
            {
                return ParseLegacyRsaPem(legacyB64, passphrase);
            }

            ReadOnlySpan<byte> ecB64 = ExtractBase64Body(fileContents, EcPemHeaderBegin, EcPemHeaderEnd);
            if (ecB64.Length > 0)
            {
                return ParseEcPem(ecB64, passphrase);
            }

            ReadOnlySpan<byte> pkcs8B64 = ExtractBase64Body(fileContents, Pkcs8HeaderBegin, Pkcs8HeaderEnd);
            if (pkcs8B64.Length > 0)
            {
                return ParsePkcs8Pem(pkcs8B64);
            }

            ReadOnlySpan<byte> encPkcs8B64 = ExtractBase64Body(fileContents, EncryptedPkcs8HeaderBegin, EncryptedPkcs8HeaderEnd);
            if (encPkcs8B64.Length > 0)
            {
                return ParseEncryptedPkcs8Pem(encPkcs8B64, passphrase);
            }

            throw new SshException(SshErrorCode.File, "PEM armor missing or OpenSSH header not found");
        }

        // Use the lenient decoder's ceiling capacity rather than the BCL strict
        // decoder's floor bound. The extra capacity holds the staged byte for
        // an unpadded partial trailing group.
        int maxDecodedLength = LenientBase64.GetMaxDecodedLength(b64.Length);
        int maxPassphraseBytes = Encoding.UTF8.GetMaxByteCount(passphrase?.Length ?? 0);
        int totalLength = maxDecodedLength + maxPassphraseBytes;

        byte[]? rented = null;
        Span<byte> buffer = (totalLength <= 256) ? stackalloc byte[256] : (rented = ArrayPool<byte>.Shared.Rent(totalLength));
        try
        {
            // libssh2's decoder skips junk and accepts unpadded tails
            // (misc.c:396-424); the BCL decoder rejects them. The lenient
            // decoder mirrors the C exactly — its only failure (a lone
            // leftover sextet) throws Inval "Invalid base64", the C's decode
            // error code.
            int decodedLength = LenientBase64.Decode(b64, buffer);

            Span<byte> decoded = buffer.Slice(0, decodedLength);

            int passphraseLength = Encoding.UTF8.GetBytes(passphrase ?? string.Empty, buffer.Slice(decodedLength));
            Span<byte> passphraseBytes = buffer.Slice(decodedLength, passphraseLength);

            return ParseOpenSshKeyData(decoded, passphraseBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
            if (rented is not null)
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }
    }

    /// <summary>
    /// Parses an already-base64-decoded OpenSSH key blob. Equivalent to
    /// libssh2's <c>_libssh2_openssh_pem_parse_data</c>.
    /// </summary>
    public static OpenSshKey ParseOpenSshKeyData(ReadOnlySpan<byte> decoded, ReadOnlySpan<byte> passphrase)
    {
        try
        {
            return ParseOpenSshKeyDataCore(decoded, passphrase);
        }
        catch (SshException ex) when (ex.ErrorCode == SshErrorCode.OutOfBoundary)
        {
            // Parity pem.c:429-678: every wire under-read inside
            // _libssh2_openssh_pem_parse_data is reported as
            // LIBSSH2_ERROR_PROTO (previously the reader's OutOfBoundary
            // escaped).
            throw new SshException(SshErrorCode.Proto, "Truncated private key data", ex);
        }
    }

    private static OpenSshKey ParseOpenSshKeyDataCore(ReadOnlySpan<byte> decoded, ReadOnlySpan<byte> passphrase)
    {
        var reader = new SshWireReader(decoded);

        // 1. Magic: "openssh-key-v1\0"
        ReadOnlySpan<byte> magic = reader.ReadBytes(AuthMagic.Length + 1);
        if (magic.Length != AuthMagic.Length + 1 ||
            Encoding.ASCII.GetString(magic.Slice(0, AuthMagic.Length)) != AuthMagic ||
            magic[AuthMagic.Length] != 0)
        {
            throw new SshException(SshErrorCode.Proto, "key auth magic mismatch");
        }

        // 2. ciphername, kdfname, kdfoptions
        ReadOnlySpan<byte> cipherName = reader.ReadSshBytes();
        ReadOnlySpan<byte> kdfName = reader.ReadSshBytes();
        ReadOnlySpan<byte> kdfOptions = reader.ReadSshBytes();

        // 3. Validate cipher + kdf combinations (mirrors the C checks).
        if (passphrase is not { Length: > 0 } && !cipherName.SequenceEqual("none"u8))
        {
            throw new SshException(SshErrorCode.KeyfileAuthFailed, "passphrase required");
        }

        if (!kdfName.SequenceEqual("none"u8) && !kdfName.SequenceEqual("bcrypt"u8))
        {
            throw new SshException(SshErrorCode.Proto, $"unknown kdf: {Encoding.ASCII.GetString(kdfName)}");
        }

        if (kdfName.SequenceEqual("none"u8) && !cipherName.SequenceEqual("none"u8))
        {
            throw new SshException(SshErrorCode.Proto, "invalid format (none kdf with non-none cipher)");
        }

        // 4. nkeys (must be 1 — libssh2 does not support multi-key files).
        uint nkeys = reader.ReadUInt32();
        if (nkeys != 1)
        {
            throw new SshException(SshErrorCode.Proto, "Multiple keys are unsupported");
        }

        // 5. Public key blob (unencrypted). Reject empty (pem.c:497-502).
        ReadOnlySpan<byte> publicKeyBlob = reader.ReadSshBytes();
        if (publicKeyBlob.Length == 0)
        {
            throw new SshException(SshErrorCode.Proto, "Invalid private key; expect embedded public key");
        }

        // 6. Private key blob (may be encrypted). Reject empty (pem.c:504-508).
        ReadOnlySpan<byte> encryptedPrivateKey = reader.ReadSshBytes();
        if (encryptedPrivateKey.Length == 0)
        {
            throw new SshException(SshErrorCode.Proto, "Private key data not found");
        }

        // For AES-GCM the 16-byte auth tag trails the private-key blob in the
        // outer stream (pem.c:645-663): it is neither length-prefixed nor part
        // of the blob read above. Read it here so the decrypt path can verify.
        bool isAesGcm = cipherName.SequenceEqual("aes256-gcm@openssh.com"u8)
            || cipherName.SequenceEqual("aes128-gcm@openssh.com"u8);
        ReadOnlySpan<byte> gcmTag = isAesGcm ? reader.ReadBytes(16) : default;

        ReadOnlySpan<byte> privateKeyBlob;
        if (cipherName.SequenceEqual("none"u8))
        {
            privateKeyBlob = encryptedPrivateKey;
        }
        else
        {
            privateKeyBlob = DecryptOpenSshPrivateKey(
                cipherName, kdfName, kdfOptions, passphrase, encryptedPrivateKey, gcmTag);
        }

        // 7. Validate check1 == check2 (wrong-passphrase detection).
        var pkReader = new SshWireReader(privateKeyBlob);
        uint check1;
        uint check2;
        try
        {
            check1 = pkReader.ReadUInt32();
            check2 = pkReader.ReadUInt32();
        }
        catch (SshException ex) when (ex.ErrorCode == SshErrorCode.OutOfBoundary)
        {
            // Parity pem.c:671-677: a decrypted blob truncated inside the
            // check bytes is treated as a wrong-passphrase failure
            // (KEYFILE_AUTH_FAILED), not a generic truncation.
            throw new SshException(SshErrorCode.KeyfileAuthFailed,
                "Private key unpack failed (correct password?)", ex);
        }

        if (check1 != check2)
        {
            throw new SshException(SshErrorCode.KeyfileAuthFailed, "Private key unpack failed (correct password?)");
        }

        // 8. The remainder of the decrypted blob is key-type-specific data
        //    (RSA modulus/exponents, Ed25519 seed+pubkey, ECDSA curve+point).
        //    Like libssh2 (which returns the decrypted buffer positioned past
        //    check1/check2), the parser returns the full decrypted blob starting
        //    at check1; SshPemKey.Parse re-reads past check1/check2/keytype and
        //    extracts the type-specific fields.

        return new OpenSshKey(
            Encoding.ASCII.GetString(cipherName),
            Encoding.ASCII.GetString(kdfName),
            publicKeyBlob.ToArray(),
            privateKeyBlob.ToArray(),
            string.Empty);
    }

    /// <summary>
    /// Decrypts the encrypted private key blob using the cipher and KDF
    /// specified. Mirrors the decryption portion of
    /// <c>_libssh2_openssh_pem_parse_data</c>.
    /// </summary>
    private static byte[] DecryptOpenSshPrivateKey(
        ReadOnlySpan<byte> cipherName,
        ReadOnlySpan<byte> kdfName,
        ReadOnlySpan<byte> kdfOptions,
        ReadOnlySpan<byte> passphrase,
        ReadOnlySpan<byte> encrypted,
        ReadOnlySpan<byte> gcmTag)
    {
        // Parse KDF options: bcrypt KDF options are (string salt, uint32 rounds).
        ReadOnlySpan<byte> salt;
        uint rounds;
        if (kdfName.SequenceEqual("bcrypt"u8))
        {
            var kdfReader = new SshWireReader(kdfOptions);
            salt = kdfReader.ReadSshBytes();
            rounds = kdfReader.ReadUInt32();

            // Bound the bcrypt round count. The C passes `rounds` to
            // bcrypt_pbkdf uncapped (a crafted file with rounds=0x7FFFFFFF runs
            // ~2.1×10⁹ bcrypt hashes — tens of minutes of CPU per parse), so
            // this is a DIVERGENCE: reject above the bound with the
            // same DECRYPT "invalid format" as the other malformed-KDF cases
            // (pem.c:561-569) BEFORE deriving.
            if (rounds > MaxBcryptRounds)
            {
                throw new SshException(SshErrorCode.Decrypt, "invalid format");
            }
        }
        else
        {
            salt = Array.Empty<byte>();
            rounds = 0;
        }

        // Derive key + IV via bcrypt PBKDF.
        (int keyLength, int ivLength, int blockSize) = GetCipherParameters(cipherName);
        byte[] derivedKey;
        try
        {
            derivedKey = BcryptPbkdf.Derive(
                passphrase,
                salt,
                rounds,
                keyLength + ivLength);
        }
        catch (ArgumentOutOfRangeException ex)
        {
            // Parity pem.c:561-569: a malformed bcrypt KDF (rounds < 1, empty
            // salt/passphrase) fails with DECRYPT "invalid format" — previously
            // the raw ArgumentOutOfRangeException escaped.
            throw new SshException(SshErrorCode.Decrypt, "invalid format", ex);
        }

        // Parity pem.c:606-610: the C rejects a ciphertext whose length is not
        // a multiple of the cipher block size with DECRYPT BEFORE decrypting.
        // The BCL's DecryptCbc would throw a raw CryptographicException first,
        // and the previous post-decrypt mirror check was dead code for CBC.
        if (encrypted.Length % blockSize != 0)
        {
            throw new SshException(SshErrorCode.Decrypt,
                "encrypted length not a multiple of block size");
        }

        byte[] key = new byte[keyLength];
        byte[] iv = new byte[ivLength];
        Array.Copy(derivedKey, 0, key, 0, keyLength);
        Array.Copy(derivedKey, keyLength, iv, 0, ivLength);

        CryptographicOperations.ZeroMemory(derivedKey);

        byte[] decrypted;
        if (cipherName.SequenceEqual("aes256-ctr"u8) || cipherName.SequenceEqual("aes192-ctr"u8) || cipherName.SequenceEqual("aes128-ctr"u8))
        {
            decrypted = AesCtrMode.Transform(encrypted, key, iv);
        }
        else if (cipherName.SequenceEqual("aes256-cbc"u8) || cipherName.SequenceEqual("aes192-cbc"u8) || cipherName.SequenceEqual("aes128-cbc"u8))
        {
            decrypted = AesCbcDecrypt(encrypted, key, iv);
        }
        else if (cipherName.SequenceEqual("aes256-gcm@openssh.com"u8) || cipherName.SequenceEqual("aes128-gcm@openssh.com"u8))
        {
            decrypted = AesGcmKeyFileDecrypt(encrypted, key, iv, gcmTag);
        }
        else
        {
            throw new SshException(SshErrorCode.Proto, $"No supported cipher found: {Encoding.ASCII.GetString(cipherName)}");
        }

        CryptographicOperations.ZeroMemory(key);
        CryptographicOperations.ZeroMemory(iv);

        // Validate that decrypted length is a multiple of the cipher block size
        // (mirrors the C check at line 606).
        if (decrypted.Length % blockSize != 0)
        {
            CryptographicOperations.ZeroMemory(decrypted);
            throw new SshException(SshErrorCode.Decrypt, "decrypted length not a multiple of block size");
        }

        return decrypted;
    }

    /// <summary>
    /// Returns (key length, IV length, block size) for the given SSH cipher name.
    /// </summary>
    private static (int KeyLength, int IvLength, int BlockSize) GetCipherParameters(ReadOnlySpan<byte> cipherName)
    {
        if (cipherName.SequenceEqual("aes128-ctr"u8))
        {
            return (16, 16, 16);
        }
        if (cipherName.SequenceEqual("aes192-ctr"u8))
        {
            return (24, 16, 16);
        }
        if (cipherName.SequenceEqual("aes256-ctr"u8))
        {
            return (32, 16, 16);
        }
        if (cipherName.SequenceEqual("aes128-cbc"u8))
        {
            return (16, 16, 16);
        }
        if (cipherName.SequenceEqual("aes192-cbc"u8))
        {
            return (24, 16, 16);
        }
        if (cipherName.SequenceEqual("aes256-cbc"u8))
        {
            return (32, 16, 16);
        }
        if (cipherName.SequenceEqual("aes128-gcm@openssh.com"u8))
        {
            return (16, 12, 16);
        }
        if (cipherName.SequenceEqual("aes256-gcm@openssh.com"u8))
        {
            return (32, 12, 16);
        }

        throw new SshException(SshErrorCode.Proto, $"No supported cipher found: {Encoding.ASCII.GetString(cipherName)}");
    }

    /// <summary>Decrypts with BCL AES-CBC (PKCS#7 padding not stripped; OpenSSH keys pad themselves).</summary>
    private static byte[] AesCbcDecrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
    {
        using var aes = Aes.Create();
        aes.SetKey(key);
        return aes.DecryptCbc(ciphertext, iv, PaddingMode.None);
    }

    /// <summary>
    /// Decrypts an AES-GCM-encrypted OpenSSH private key blob. Unlike the SSH
    /// transport path (RFC 5647 fixed-prefix + invocation-counter nonce scheme,
    /// 4-byte length authenticated as AAD), the OpenSSH key-file format uses the
    /// raw 12-byte derived IV as the GCM nonce with no AAD, and stores the
    /// 16-byte auth tag as trailing bytes in the outer stream
    /// (<c>pem.c:612-664</c>, <c>openssl.c:1042</c> — libssh2 always passes
    /// <c>MIDDLE_BLOCK</c> so <c>aadlen == 0</c>). Decrypting the whole blob in
    /// one shot is cryptographically identical to libssh2's per-block feed.
    /// </summary>
    private static byte[] AesGcmKeyFileDecrypt(
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> iv,
        ReadOnlySpan<byte> tag)
    {
        if (tag.Length != 16)
        {
            throw new SshException(SshErrorCode.Proto, "GCM auth tag missing");
        }

        if (iv.Length != 12)
        {
            throw new SshException(SshErrorCode.Proto, "GCM IV must be 12 bytes");
        }

        byte[] plaintext = new byte[ciphertext.Length];
        try
        {
            using var gcm = new AesGcm(key, 16);
            gcm.Decrypt(iv, ciphertext, tag, plaintext, default);
        }
        catch (CryptographicException)
        {
            CryptographicOperations.ZeroMemory(plaintext);
            // Tag verification failed — wrong passphrase (wrong derived key) or
            // corrupted ciphertext. Normalized to KeyfileAuthFailed so the
            // wrong-passphrase error is uniform across all ciphers (CTR/CBC
            // detect it via check1 != check2 instead).
            throw new SshException(
                SshErrorCode.KeyfileAuthFailed,
                "Private key unpack failed (correct password?)");
        }

        return plaintext;
    }

    /// <summary>
    /// Extracts the base64 body between <paramref name="beginMarker"/> and
    /// <paramref name="endMarker"/>, without stripping whitespace. Similar to
    /// libssh2's armor-stripping logic in
    /// <c>_libssh2_openssh_pem_parse_memory</c>.
    /// </summary>
    private static ReadOnlySpan<byte> ExtractBase64Body(ReadOnlySpan<byte> text, ReadOnlySpan<byte> beginMarker, ReadOnlySpan<byte> endMarker)
    {
        // Parity pem.c:800-865: the C compares WHOLE LINES against the markers
        // (readline_memory strips only the line terminator, pem.c:81-96, then
        // strcmp), so a marker embedded mid-line or with trailing junk on its
        // line is NOT a header. The previous IndexOf matched anywhere,
        // accepting files the C rejects.
        int beginIdx = IndexOfAtLineStart(text, beginMarker);
        if (beginIdx < 0)
        {
            return ReadOnlySpan<byte>.Empty;
        }

        // Skip the marker line plus newline.
        int bodyStart = beginIdx + beginMarker.Length;

        int endIdx = IndexOfAtLineStart(text.Slice(bodyStart), endMarker);
        if (endIdx < 0)
        {
            return ReadOnlySpan<byte>.Empty;
        }

        ReadOnlySpan<byte> body = text.Slice(bodyStart, endIdx);

        return body;
    }

    /// <summary>
    /// Finds <paramref name="marker"/> at the start of a line (position 0 or
    /// after a <c>\n</c>), where the line is exactly the marker (the next byte
    /// is <c>\n</c>, <c>\r</c>, or end-of-input). Mirrors the C's
    /// whole-line <c>strcmp</c> matching.
    /// </summary>
    private static int IndexOfAtLineStart(ReadOnlySpan<byte> text, ReadOnlySpan<byte> marker)
    {
        if (marker.Length > text.Length)
        {
            return -1;
        }

        int pos = 0;
        while (pos <= text.Length - marker.Length)
        {
            if (text.Slice(pos, marker.Length).SequenceEqual(marker)
                && (pos + marker.Length == text.Length
                    || text[pos + marker.Length] is (byte)'\n' or (byte)'\r'))
            {
                return pos;
            }

            int nl = text.Slice(pos).IndexOf((byte)'\n');
            if (nl < 0)
            {
                return -1;
            }

            pos += nl + 1;
        }

        return -1;
    }

    // ════════════════════════════════════════════════════════════════════════
    // Legacy PEM (PKCS#1 RSA, unencrypted + traditional encrypted)
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Parses a <c>-----BEGIN RSA PRIVATE KEY-----</c> body, dispatching on
    /// the traditional PEM headers: unencrypted PKCS#1 DER, or
    /// <c>Proc-Type: 4,ENCRYPTED</c> with
    /// <c>DEK-Info: &lt;cipher&gt;,&lt;hex-iv&gt;</c>. For encrypted keys the
    /// base64 body is PURE ciphertext (OpenSSL 3.x — no salt prefix): the
    /// DEK-Info hex value is the CBC IV, and the key comes from
    /// <c>EVP_BytesToKey(MD5, count=1)</c> with the first 8 IV bytes as the
    /// salt (PKCS5_SALT_LEN; pem_lib.c:345-385 writer, pem_lib.c:416-460
    /// reader). A wrong passphrase surfaces as a PKCS#7 padding failure,
    /// mapped to <see cref="SshErrorCode.KeyfileAuthFailed"/> — the C's
    /// BAD_DECRYPT mapping (openssl.c:5036-5041); malformed headers map to
    /// <see cref="SshErrorCode.File"/> like the C's non-BAD_DECRYPT failures
    /// (openssl.c:5043-5047).
    /// </summary>
    private static OpenSshKey ParseLegacyRsaPem(ReadOnlySpan<byte> body, string? passphrase)
    {
        (bool encrypted, string? dekCipher, string? dekIvHex) = SplitLegacyHeaders(body, out ReadOnlySpan<byte> b64);

        byte[] buffer = ArrayPool<byte>.Shared.Rent(LenientBase64.GetMaxDecodedLength(b64.Length));
        try
        {
            int decodedLength = LenientBase64.Decode(b64, buffer);
            Span<byte> decoded = buffer.AsSpan(0, decodedLength);

            if (!encrypted)
            {
                // Unencrypted PKCS#1 — a supplied passphrase is silently
                // ignored (parity with the C's quirk for unencrypted keys).
                return ParseLegacyRsaPrivateKey(decoded);
            }

            return ParseLegacyRsaPrivateKey(DecryptTraditionalPemBody(dekCipher, dekIvHex, decoded, passphrase));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Decrypts a traditional-encrypted PEM body (Proc-Type: 4,ENCRYPTED +
    /// DEK-Info) following OpenSSL 3.x's <c>PEM_do_header</c> exactly: the
    /// base64 body is pure ciphertext, the DEK-Info hex value is the CBC IV,
    /// and <c>EVP_BytesToKey(MD5, count=1)</c> derives only the key from the
    /// first 8 IV bytes (PKCS5_SALT_LEN; pem_lib.c:345-385, 416-460).
    /// Shared by the PKCS#1 and SEC1 EC legacy paths.
    /// </summary>
    private static byte[] DecryptTraditionalPemBody(string? dekCipher, string? dekIvHex, ReadOnlySpan<byte> decoded, string? passphrase)
    {
        if (passphrase is not { Length: > 0 })
        {
            // OpenSSL's PEM_def_callback rejects a missing passphrase
            // (PEM_R_BAD_PASSWORD_READ) — the C maps the failed read to
            // KEYFILE_AUTH_FAILED.
            throw new SshException(SshErrorCode.KeyfileAuthFailed,
                "Passphrase required for encrypted private key");
        }

        if (dekCipher is null || dekIvHex is null)
        {
            // Headers OpenSSL rejects outright (PEM_R_NOT_DEK_INFO,
            // PEM_R_MISSING_DEK_IV, …) — the C's plain FILE error.
            throw new SshException(SshErrorCode.File,
                "Unsupported private key file format");
        }

        (int keyLen, int ivLen) = CipherKeyIvLengths(dekCipher);
        byte[] iv;
        try
        {
            iv = Convert.FromHexString(dekIvHex);
        }
        catch (FormatException)
        {
            // load_iv's bad-iv-chars failure (pem_lib.c:557-576).
            throw new SshException(SshErrorCode.File,
                "Unsupported private key file format");
        }

        if (iv.Length != ivLen)
        {
            // load_iv reads exactly 2*ivlen hex chars (pem_lib.c:559-575).
            throw new SshException(SshErrorCode.File,
                "Unsupported private key file format");
        }

        byte[] key = EvpBytesToKey(passphrase, iv.AsSpan(0, 8), keyLen);
        try
        {
            return DecryptTraditionalPem(dekCipher, decoded, key, iv);
        }
        catch (CryptographicException)
        {
            // PKCS#7 padding check failed — the C's PEM_R_BAD_DECRYPT /
            // EVP_R_BAD_DECRYPT → KEYFILE_AUTH_FAILED (openssl.c:5036-5041).
            throw new SshException(SshErrorCode.KeyfileAuthFailed,
                "Wrong passphrase for private key");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <summary>
    /// Parses a SEC1 <c>-----BEGIN EC PRIVATE KEY-----</c> body (RFC 5915),
    /// unencrypted or traditional-encrypted (Proc-Type/DEK-Info — the same
    /// scheme as PKCS#1). libssh2 accepts these via
    /// <c>PEM_read_bio_PrivateKey</c> + <c>gen_publickey_from_ec_evp</c>
    /// (openssl.c:5016, 5076-5080); curves supported: nistp256/384/521.
    /// </summary>
    private static OpenSshKey ParseEcPem(ReadOnlySpan<byte> body, string? passphrase)
    {
        (bool encrypted, string? dekCipher, string? dekIvHex) = SplitLegacyHeaders(body, out ReadOnlySpan<byte> b64);

        byte[] buffer = ArrayPool<byte>.Shared.Rent(LenientBase64.GetMaxDecodedLength(b64.Length));
        try
        {
            int decodedLength = LenientBase64.Decode(b64, buffer);
            Span<byte> decoded = buffer.AsSpan(0, decodedLength);

            if (!encrypted)
            {
                // Unencrypted SEC1 — a supplied passphrase is silently
                // ignored (OpenSSL never asks on an unencrypted key).
                return ParseSec1PrivateKey(decoded, null);
            }

            return ParseSec1PrivateKey(DecryptTraditionalPemBody(dekCipher, dekIvHex, decoded, passphrase), null);
        }
        catch (SshException ex) when (ex.ErrorCode == SshErrorCode.Proto)
        {
            // Structural DER failure — the C's d2i failure → the plain FILE
            // error (openssl.c:5043-5047).
            throw new SshException(SshErrorCode.File, "Unsupported private key file format", ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Parses an SEC1 ECPrivateKey DER payload (RFC 5915):
    /// <c>SEQUENCE { version, privateKey OCTET STRING, parameters [0] OID,
    /// publicKey [1] BIT STRING }</c>. The <c>[0]</c> namedCurve may be
    /// absent when the curve came from a PKCS#8 wrapper
    /// (<paramref name="curveNameFromPkcs8"/>); the <c>[1]</c> public point
    /// may be absent (recomputed from the private scalar). The key is
    /// rebuilt as OpenSSH-format ecdsa blobs (public:
    /// <c>[string "ecdsa-sha2-nistpXXX"][string "nistpXXX"][string Q]</c> —
    /// byte-identical to <c>gen_publickey_from_ec_evp</c>, openssl.c:3496-3534;
    /// private: <c>check1‖check2‖keytype‖curve‖Q‖d‖comment</c> — the
    /// ssh-keygen wire format).
    /// </summary>
    private static OpenSshKey ParseSec1PrivateKey(ReadOnlySpan<byte> der, string? curveNameFromPkcs8)
    {
        var outer = new DerReader(der);
        outer.ExpectSequence(out ReadOnlySpan<byte> seq);
        var r = new DerReader(seq);

        _ = r.ReadInteger();   // version (1; not validated — OpenSSL is equally lenient)
        byte[] d = r.ReadOctetString().ToArray();

        string? curveName = curveNameFromPkcs8;
        byte[]? point = null;
        while (!r.AtEnd)
        {
            switch (r.PeekTag())
            {
                case 0xA0:
                    // [0] parameters: namedCurve OID (implicit ECParameters).
                    var c0 = new DerReader(r.ReadTagged(0xA0));
                    curveName = CurveNameFromOid(c0.ReadOid());
                    break;
                case 0xA1:
                    // [1] publicKey BIT STRING. OpenSSL writes it with
                    // EXPLICIT tagging ([1] { BIT STRING { 00 ‖ point } }),
                    // RFC 5915's module is IMPLICIT ([1] content = 00 ‖
                    // point); d2i accepts both — so do we.
                    ReadOnlySpan<byte> c1 = r.ReadTagged(0xA1);
                    if (c1.Length > 0 && c1[0] == 0x03)
                    {
                        var bs = new DerReader(c1);
                        c1 = bs.ReadTagged(0x03);
                    }

                    if (c1.Length < 1 || c1[0] != 0)
                    {
                        throw new SshException(SshErrorCode.Proto, "Invalid EC private key (DER)");
                    }

                    point = c1[1..].ToArray();
                    break;
                default:
                    throw new SshException(SshErrorCode.Proto, "Invalid EC private key (DER)");
            }
        }

        if (curveName is null)
        {
            // SEC1 without [0] needs the PKCS#8 wrapper's namedCurve.
            throw new SshException(SshErrorCode.File, "Unsupported private key file format");
        }

        ECCurve curve = curveName switch
        {
            "nistp256" => ECCurve.NamedCurves.nistP256,
            "nistp384" => ECCurve.NamedCurves.nistP384,
            "nistp521" => ECCurve.NamedCurves.nistP521,
            _ => throw new SshException(SshErrorCode.File, "Unsupported private key file format"),
        };

        point ??= ComputePublicPoint(curve, d);

        byte[] publicBlob = BuildSshEcdsaPublicBlob(curveName, point);
        byte[] privateBlob = BuildOpenSshEcdsaPrivateBlob(curveName, point, d);
        return new OpenSshKey("none", "none", publicBlob, privateBlob, string.Empty);
    }

    /// <summary>
    /// Computes the uncompressed SEC1 public point (0x04 ‖ X ‖ Y) for a
    /// private scalar — what OpenSSL does when SEC1's <c>[1]</c> publicKey
    /// is absent.
    /// </summary>
    private static byte[] ComputePublicPoint(ECCurve curve, byte[] d)
    {
        using var ecdsa = ECDsa.Create(curve);
        ecdsa.ImportParameters(new ECParameters { Curve = curve, D = d });
        ECParameters exported = ecdsa.ExportParameters(false);
        byte[] point = new byte[1 + exported.Q.X!.Length + exported.Q.Y!.Length];
        point[0] = 0x04;
        exported.Q.X.CopyTo(point, 1);
        exported.Q.Y.CopyTo(point, 1 + exported.Q.X.Length);
        return point;
    }

    /// <summary>
    /// Builds an ecdsa public key blob: <c>[string "ecdsa-sha2-nistpXXX"]
    /// [string "nistpXXX"][string Q]</c> — the C's exact construction
    /// (openssl.c:3496-3534, byte-identical to ssh-keygen's .pub output).
    /// </summary>
    private static byte[] BuildSshEcdsaPublicBlob(string curveName, byte[] point)
    {
        using var ms = new MemoryStream(128);
        WriteSshString(ms, Encoding.ASCII.GetBytes("ecdsa-sha2-" + curveName));
        WriteSshString(ms, Encoding.ASCII.GetBytes(curveName));
        WriteSshString(ms, point);
        return ms.ToArray();
    }

    /// <summary>
    /// Builds an OpenSSH new-format private key blob (check1‖check2‖keytype‖
    /// curve‖Q‖d‖comment) for an ECDSA key — the ssh-keygen wire format
    /// (d as a plain big-endian string, no mpint sign byte; verified against
    /// real ssh-keygen output). Matches <see cref="SshPemKey"/>'s parser.
    /// </summary>
    private static byte[] BuildOpenSshEcdsaPrivateBlob(string curveName, byte[] point, byte[] d)
    {
        byte[] check = new byte[4];
        RandomNumberGenerator.Fill(check);

        using var ms = new MemoryStream(256);
        ms.Write(check, 0, 4);          // check1
        ms.Write(check, 0, 4);          // check2 (equal — the parser only compares)
        WriteSshString(ms, Encoding.ASCII.GetBytes("ecdsa-sha2-" + curveName));
        WriteSshString(ms, Encoding.ASCII.GetBytes(curveName));
        WriteSshString(ms, point);
        WriteSshString(ms, d);
        WriteSshString(ms, []);          // empty comment
        return ms.ToArray();
    }

    /// <summary>
    /// Maps a namedCurve OID to the OpenSSH curve name. Unknown curves are
    /// the C's unsupported-EC-type failure (gen_publickey_from_ec_evp,
    /// openssl.c:3490-3494) — mapped to the user-facing FILE error.
    /// </summary>
    private static string CurveNameFromOid(ReadOnlySpan<byte> oid)
    {
        // prime256v1 1.2.840.10045.3.1.7
        if (oid.SequenceEqual((ReadOnlySpan<byte>)[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]))
        {
            return "nistp256";
        }

        // secp384r1 1.3.132.0.34
        if (oid.SequenceEqual((ReadOnlySpan<byte>)[0x2B, 0x81, 0x04, 0x00, 0x22]))
        {
            return "nistp384";
        }

        // secp521r1 1.3.132.0.35
        if (oid.SequenceEqual((ReadOnlySpan<byte>)[0x2B, 0x81, 0x04, 0x00, 0x23]))
        {
            return "nistp521";
        }

        throw new SshException(SshErrorCode.File, "Unsupported private key file format");
    }

    /// <summary>
    /// Extracts the 32-byte Ed25519 seed from the PKCS#8 privateKey OCTET
    /// STRING content: either RFC 8410's literal form (the raw 32 bytes) or
    /// OpenSSL's nested form (an inner OCTET STRING wrapping the 32 bytes).
    /// </summary>
    private static byte[] UnwrapEd25519Seed(ReadOnlySpan<byte> content)
    {
        if (content.Length == 32)
        {
            return content.ToArray();
        }

        if (content.Length > 1 && content[0] == 0x04)
        {
            var inner = new DerReader(content);
            ReadOnlySpan<byte> seed = inner.ReadOctetString();
            if (seed.Length == 32)
            {
                return seed.ToArray();
            }
        }

        throw new SshException(SshErrorCode.File, "Unsupported private key file format");
    }

    /// <summary>
    /// Builds an ssh-ed25519 public key blob: <c>[string "ssh-ed25519"]
    /// [string A(32)]</c> — the C's exact construction
    /// (gen_publickey_from_ed_evp, openssl.c:2196-2218, byte-identical to
    /// ssh-keygen's .pub output).
    /// </summary>
    private static byte[] BuildSshEd25519PublicBlob(byte[] publicKey)
    {
        using var ms = new MemoryStream(64);
        WriteSshString(ms, "ssh-ed25519"u8);
        WriteSshString(ms, publicKey);
        return ms.ToArray();
    }

    /// <summary>
    /// Builds an OpenSSH new-format private key blob for Ed25519:
    /// <c>check1‖check2‖keytype‖A‖(seed‖A)‖comment</c> — the ssh-keygen wire
    /// format (the 64-byte private field is seed ‖ public; verified against
    /// real ssh-keygen output). Matches <see cref="SshPemKey"/>'s parser
    /// (openssl.c:2259-2286).
    /// </summary>
    private static byte[] BuildOpenSshEd25519PrivateBlob(byte[] publicKey, byte[] seed)
    {
        byte[] check = new byte[4];
        RandomNumberGenerator.Fill(check);

        using var ms = new MemoryStream(128);
        ms.Write(check, 0, 4);          // check1
        ms.Write(check, 0, 4);          // check2 (equal — the parser only compares)
        WriteSshString(ms, "ssh-ed25519"u8);
        WriteSshString(ms, publicKey);
        byte[] priv = new byte[seed.Length + publicKey.Length];
        seed.CopyTo(priv, 0);
        publicKey.CopyTo(priv, seed.Length);
        WriteSshString(ms, priv);
        WriteSshString(ms, []);          // empty comment
        return ms.ToArray();
    }

    /// <summary>
    /// Parses an unencrypted PKCS#8 <c>-----BEGIN PRIVATE KEY-----</c> body
    /// (RFC 5208 PrivateKeyInfo) with RSA (rsaEncryption), EC
    /// (id-ecPublicKey + namedCurve), or Ed25519 (id-Ed25519) inner keys.
    /// DSA/X25519 etc. map to the user-facing <see cref="SshErrorCode.File"/>
    /// error — for DSA the C parses it (openssl.c:5070-5073, deferred here);
    /// for X25519 the C rejects it too (default case, openssl.c:5081-5088).
    /// A supplied passphrase is silently ignored (OpenSSL never asks for one
    /// on an unencrypted key).
    /// </summary>
    private static OpenSshKey ParsePkcs8Pem(ReadOnlySpan<byte> body)
    {
        byte[] buffer = ArrayPool<byte>.Shared.Rent(LenientBase64.GetMaxDecodedLength(body.Length));
        try
        {
            int decodedLength = LenientBase64.Decode(body, buffer);
            Span<byte> decoded = buffer.AsSpan(0, decodedLength);

            return ParsePkcs8PrivateKeyInfo(decoded);
        }
        catch (SshException ex) when (ex.ErrorCode == SshErrorCode.Proto)
        {
            // Structural DER failure — the C's d2i failure, which is not
            // BAD_DECRYPT, so it maps to the plain FILE error
            // (openssl.c:5043-5047).
            throw new SshException(SshErrorCode.File, "Unsupported private key file format", ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Parses a PKCS#8 EncryptedPrivateKeyInfo
    /// (<c>-----BEGIN ENCRYPTED PRIVATE KEY-----</c>) with the PBES2 scheme
    /// (RFC 8018): PBKDF2 key derivation (HMAC-SHA1 or HMAC-SHA256 PRF) +
    /// AES-128/192/256-CBC or DES-EDE3-CBC. These are what OpenSSL 3.x emits
    /// for encrypted PKCS#8 (its PBES1 path is legacy-provider-only). The
    /// decrypted payload is a PrivateKeyInfo parsed by
    /// <see cref="ParsePkcs8PrivateKeyInfo"/>. Error mapping matches the C:
    /// a PBKDF2-derived wrong key fails the PKCS#7 padding check →
    /// <see cref="SshErrorCode.KeyfileAuthFailed"/> (the C's BAD_DECRYPT,
    /// openssl.c:5036-5041); structural failures → <see cref="SshErrorCode.File"/>
    /// (openssl.c:5043-5047).
    /// </summary>
    private static OpenSshKey ParseEncryptedPkcs8Pem(ReadOnlySpan<byte> body, string? passphrase)
    {
        byte[] buffer = ArrayPool<byte>.Shared.Rent(LenientBase64.GetMaxDecodedLength(body.Length));
        try
        {
            int decodedLength = LenientBase64.Decode(body, buffer);
            Span<byte> decoded = buffer.AsSpan(0, decodedLength);

            return ParseEncryptedPkcs8Der(decoded, passphrase);
        }
        catch (SshException ex) when (ex.ErrorCode == SshErrorCode.Proto)
        {
            // Structural DER failure — the C's d2i failure, which is not
            // BAD_DECRYPT, so it maps to the plain FILE error
            // (openssl.c:5043-5047).
            throw new SshException(SshErrorCode.File, "Unsupported private key file format", ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static OpenSshKey ParseEncryptedPkcs8Der(ReadOnlySpan<byte> decoded, string? passphrase)
    {
        var outer = new DerReader(decoded);
        outer.ExpectSequence(out ReadOnlySpan<byte> seq);
        var r = new DerReader(seq);
        int? requestedKeyLength = null;

        // encryptionAlgorithm AlgorithmIdentifier { PBES2, PBES2-params }
        r.ExpectSequence(out ReadOnlySpan<byte> algId);
        var a = new DerReader(algId);
        if (!a.ReadOid().SequenceEqual(Pkcs8OidPbes2))
        {
            // PBES1 and any other scheme (legacy-provider-only in modern
            // OpenSSL; unreachable for files this OpenSSL build writes).
            throw new SshException(SshErrorCode.File, "Unsupported private key file format");
        }

        a.ExpectSequence(out ReadOnlySpan<byte> pbes2Params);
        var p = new DerReader(pbes2Params);

        // keyDerivationFunc AlgorithmIdentifier { PBKDF2, PBKDF2-params }
        p.ExpectSequence(out ReadOnlySpan<byte> kdf);
        var k = new DerReader(kdf);
        if (!k.ReadOid().SequenceEqual(Pkcs8OidPbkdf2))
        {
            throw new SshException(SshErrorCode.File, "Unsupported private key file format");
        }

        k.ExpectSequence(out ReadOnlySpan<byte> pbkdf2Params);
        var pb = new DerReader(pbkdf2Params);
        byte[] salt = pb.ReadOctetString().ToArray();
        long iterations = DerIntegerToLong(pb.ReadInteger());
        // Bound the PBKDF2 iteration count. The C delegates PKCS#8 to
        // OpenSSL, which runs any iteration count up to int.MaxValue (a crafted
        // file pins the CPU for hours) — the cap is a DIVERGENCE,
        // rejected with the same FILE error as the other out-of-range gates
        // before deriving.
        if (iterations is <= 0 or > MaxPbkdf2Iterations)
        {
            throw new SshException(SshErrorCode.File, "Unsupported private key file format");
        }

        if (!pb.AtEnd && pb.PeekTag() == 0x02)
        {
            // Optional keyLength INTEGER (RFC 8018 A.2); must match the
            // cipher's key length or OpenSSL's PBKDF2/decrypt fails.
            long keyLength = DerIntegerToLong(pb.ReadInteger());
            if (keyLength is <= 0 or > int.MaxValue)
            {
                throw new SshException(SshErrorCode.File, "Unsupported private key file format");
            }

            requestedKeyLength = (int)keyLength;
        }
        // Optional PRF AlgorithmIdentifier; absent → HMAC-SHA1 (the
        // RFC 8018 default, matching OpenSSL's PBKDF2params handling).
        HashAlgorithmName prf = HashAlgorithmName.SHA1;
        if (!pb.AtEnd && pb.PeekTag() == 0x30)
        {
            pb.ExpectSequence(out ReadOnlySpan<byte> prfSeq);
            var pr = new DerReader(prfSeq);
            ReadOnlySpan<byte> prfOid = pr.ReadOid();
            if (prfOid.SequenceEqual(Pkcs8OidHmacWithSha256))
            {
                prf = HashAlgorithmName.SHA256;
            }
            else if (!prfOid.SequenceEqual(Pkcs8OidHmacWithSha1))
            {
                throw new SshException(SshErrorCode.File, "Unsupported private key file format");
            }
        }

        // encryptionScheme AlgorithmIdentifier { cipher, IV }
        p.ExpectSequence(out ReadOnlySpan<byte> enc);
        var e = new DerReader(enc);
        string cipherName = Pkcs8CipherFromOid(e.ReadOid());
        byte[] iv = e.ReadOctetString().ToArray();
        (int keyLen, int ivLen) = CipherKeyIvLengths(cipherName);
        if (iv.Length != ivLen)
        {
            // IV length mismatch — OpenSSL's decrypt fails with a
            // non-BAD_DECRYPT error → the C's plain FILE error.
            throw new SshException(SshErrorCode.File, "Unsupported private key file format");
        }

        if (passphrase is not { Length: > 0 })
        {
            // OpenSSL's PEM_def_callback rejects a missing passphrase
            // (PEM_R_BAD_PASSWORD_READ) — the C maps the failed read to
            // KEYFILE_AUTH_FAILED (same as PKCS#1).
            throw new SshException(SshErrorCode.KeyfileAuthFailed,
                "Passphrase required for encrypted private key");
        }

        if (requestedKeyLength is int requested && requested != keyLen)
        {
            throw new SshException(SshErrorCode.File, "Unsupported private key file format");
        }

        byte[] key = Pbkdf2(passphrase, salt, (int)iterations, prf, keyLen);
        try
        {
            ReadOnlySpan<byte> ciphertext = r.ReadOctetString();
            byte[] plain = DecryptTraditionalPem(cipherName, ciphertext, key, iv);
            return ParsePkcs8PrivateKeyInfo(plain);
        }
        catch (CryptographicException)
        {
            // PKCS#7 padding check failed — the C's BAD_DECRYPT →
            // KEYFILE_AUTH_FAILED (openssl.c:5036-5041).
            throw new SshException(SshErrorCode.KeyfileAuthFailed,
                "Wrong passphrase for private key");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(iv);
        }
    }

    /// <summary>
    /// Parses an unencrypted PKCS#8 PrivateKeyInfo DER payload:
    /// <c>SEQUENCE { version, AlgorithmIdentifier { rsaEncryption, NULL },
    /// OCTET STRING (PKCS#1 DER) }</c>. The inner key is parsed by
    /// <see cref="ParseLegacyRsaPrivateKey"/>; errors map to
    /// <see cref="SshErrorCode.File"/> "Unsupported private key file format"
    /// — the user-facing libssh2 mapping (openssl.c:5043-5047).
    /// </summary>
    private static OpenSshKey ParsePkcs8PrivateKeyInfo(ReadOnlySpan<byte> der)
    {
        var outer = new DerReader(der);
        outer.ExpectSequence(out ReadOnlySpan<byte> seq);
        var r = new DerReader(seq);

        _ = r.ReadInteger();   // version (must be 0; not validated)
        r.ExpectSequence(out ReadOnlySpan<byte> algId);
        var a = new DerReader(algId);
        ReadOnlySpan<byte> algorithmOid = a.ReadOid();
        if (algorithmOid.SequenceEqual(Pkcs8OidRsaEncryption))
        {
            if (!a.AtEnd)
            {
                a.SkipElement();   // rsaEncryption parameters (usually NULL)
            }

            return ParseLegacyRsaPrivateKey(r.ReadOctetString());
        }

        if (algorithmOid.SequenceEqual(Pkcs8OidEcPublicKey))
        {
            // id-ecPublicKey parameters = the namedCurve OID (RFC 5480);
            // the inner OCTET STRING is the SEC1 ECPrivateKey structure.
            string curveName = CurveNameFromOid(a.ReadOid());
            return ParseSec1PrivateKey(r.ReadOctetString(), curveName);
        }

        if (algorithmOid.SequenceEqual(Pkcs8OidEd25519))
        {
            // id-Ed25519 (RFC 8410): parameters absent/NULL; the inner OCTET
            // STRING is the 32-byte seed. OpenSSL encodes the seed as a
            // NESTED OCTET STRING (04 22 { 04 20 { seed } }) — its
            // "curve-style" convention — while RFC 8410's literal form is
            // the raw 32 bytes; OpenSSL's decoder accepts both, so do we.
            // An optional [1] BIT STRING public key may follow (validated
            // against the derived key).
            if (!a.AtEnd)
            {
                a.SkipElement();   // NULL parameters (RFC 8410: absent or NULL)
            }

            byte[] seed = UnwrapEd25519Seed(r.ReadOctetString());
            byte[] publicKey = Ed25519.GetPublicKey(seed);
            if (!r.AtEnd && r.PeekTag() == 0xA1)
            {
                // [1] IMPLICIT BIT STRING = 0x00 unused-bits ‖ public key.
                // OpenSSL rejects a missing/mismatched embedded public key
                // (verified empirically: `openssl pkey` fails to read a
                // PKCS#8 whose [1] differs from the derived key) — the
                // failure maps to the C's plain FILE error.
                ReadOnlySpan<byte> c1 = r.ReadTagged(0xA1);
                if (c1.Length != 33 || c1[0] != 0 || !c1[1..].SequenceEqual(publicKey))
                {
                    throw new SshException(SshErrorCode.File, "Unsupported private key file format");
                }
            }

            return new OpenSshKey(
                "none", "none",
                BuildSshEd25519PublicBlob(publicKey),
                BuildOpenSshEd25519PrivateBlob(publicKey, seed),
                string.Empty);
        }

        // DSA/X25519/etc. PKCS#8 — the C's default case rejects these with
        // the same FILE error (openssl.c:5081-5088); parity.
        throw new SshException(SshErrorCode.File, "Unsupported private key file format");
    }

    /// <summary>
    /// PBKDF2 (RFC 8018 §5.2) with the given PRF — the C's
    /// <c>PKCS5_PBKDF2_HMAC</c> call inside OpenSSL's PKCS8_decrypt.
    /// </summary>
    private static byte[] Pbkdf2(string passphrase, byte[] salt, int iterations, HashAlgorithmName prf, int keyLen)
    {
        byte[] pass = Encoding.UTF8.GetBytes(passphrase);
        try
        {
            return Rfc2898DeriveBytes.Pbkdf2(pass, salt, iterations, prf, keyLen);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pass);
        }
    }

    /// <summary>
    /// DER INTEGER content → long (the value may carry a leading 0x00 sign
    /// byte, which <see cref="DerReader.ReadInteger"/> strips). Content
    /// longer than 8 bytes is REJECTED — the unchecked shift-accumulate would
    /// silently wrap a crafted over-long INTEGER (e.g. a 9-byte positive value)
    /// to a small number, passing the iterations/keyLength gates where
    /// OpenSSL's <c>ASN1_INTEGER_get</c> (which fails for
    /// <c>length &gt; sizeof(long)</c>) rejects the file.
    /// </summary>
    private static long DerIntegerToLong(byte[] value)
    {
        if (value.Length > sizeof(long))
        {
            throw new SshException(SshErrorCode.File, "Unsupported private key file format");
        }

        long result = 0;
        foreach (byte b in value)
        {
            result = (result << 8) | b;
        }

        return result;
    }

    /// <summary>
    /// Splits the legacy PEM body into the optional <c>Proc-Type</c>/
    /// <c>DEK-Info</c> headers and the base64 payload. Returns the header
    /// flag/cipher/IV-hex and hands the base64 span back via
    /// <paramref name="base64"/> (a ref struct cannot ride in the tuple).
    /// </summary>
    private static (bool Encrypted, string? DekCipher, string? DekIvHex) SplitLegacyHeaders(ReadOnlySpan<byte> body, out ReadOnlySpan<byte> base64)
    {
        bool encrypted = false;
        string? dekCipher = null;
        string? dekIvHex = null;
        int pos = 0;
        while (pos < body.Length)
        {
            int eol = body.Slice(pos).IndexOf((byte)'\n');
            ReadOnlySpan<byte> line = eol < 0 ? body[pos..] : body.Slice(pos, eol);
            if (line.Length > 0 && line[^1] == (byte)'\r')
            {
                line = line[..^1];
            }

            if (line.Length == 0)
            {
                // Blank separator after the headers.
                pos = eol < 0 ? body.Length : pos + eol + 1;
                if (eol < 0)
                {
                    break;
                }

                continue;
            }

            if (line.StartsWith("Proc-Type: 4,ENCRYPTED"u8))
            {
                encrypted = true;
            }
            else if (line.StartsWith("DEK-Info: "u8))
            {
                // "DEK-Info: <cipher>,<hex-iv>"
                ReadOnlySpan<byte> rest = line.Slice("DEK-Info: "u8.Length);
                int comma = rest.IndexOf((byte)',');
                if (comma >= 0)
                {
                    dekCipher = Encoding.ASCII.GetString(rest[..comma]);
                    dekIvHex = Encoding.ASCII.GetString(rest[(comma + 1)..]);
                }
            }
            else
            {
                break;   // first base64 line
            }

            pos = eol < 0 ? body.Length : pos + eol + 1;
            if (eol < 0)
            {
                break;
            }
        }

        base64 = body[pos..];
        return (encrypted, dekCipher, dekIvHex);
    }

    /// <summary>
    /// OpenSSL's <c>EVP_BytesToKey</c> with MD5 and iteration count 1 — the
    /// traditional PEM key derivation: <c>D_1 = MD5(pass ‖ salt)</c>,
    /// <c>D_{i&gt;1} = MD5(D_{i-1} ‖ pass ‖ salt)</c>, output truncated to
    /// the requested length (pem_lib.c:449-451; the OpenSSL default scheme).
    /// The salt is at most PKCS5_SALT_LEN (8) bytes — the caller passes the
    /// first 8 IV bytes, matching <c>EVP_BytesToKey</c>'s salt handling.
    /// </summary>
    [SuppressMessage("Security", "CA5351:Do not use insecure cryptographic algorithms", Justification = "MD5 is the traditional PEM key derivation (EVP_BytesToKey with count=1); parity with OpenSSL's PEM_do_header — required to decrypt legacy keys the caller opted into.")]
    private static byte[] EvpBytesToKey(string passphrase, ReadOnlySpan<byte> salt, int length)
    {
        byte[] pass = Encoding.UTF8.GetBytes(passphrase);
        try
        {
            byte[] result = new byte[length];
            byte[]? prev = null;
            int done = 0;
            while (done < length)
            {
                byte[] input = new byte[(prev?.Length ?? 0) + pass.Length + salt.Length];
                int offset = 0;
                if (prev is not null)
                {
                    prev.CopyTo(input, 0);
                    offset += prev.Length;
                }

                pass.CopyTo(input, offset);
                offset += pass.Length;
                salt.CopyTo(input.AsSpan(offset));

                byte[] digest = MD5.HashData(input);
                int copy = Math.Min(digest.Length, length - done);
                digest.AsSpan(0, copy).CopyTo(result.AsSpan(done));
                done += digest.Length;
                prev = digest;
            }

            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pass);
        }
    }

    /// <summary>
    /// Key and IV lengths of the traditional-PEM ciphers OpenSSL accepts for
    /// legacy RSA keys (ssh-keygen/OpenSSL emit only these). An unknown name
    /// is OpenSSL's <c>EVP_get_cipherbyname</c> failure (PEM_R_UNSUPPORTED_
    /// ENCRYPTION) — the C's plain FILE error (openssl.c:5043-5047).
    /// </summary>
    private static (int KeyLen, int IvLen) CipherKeyIvLengths(string cipherName) => cipherName switch
    {
        "AES-128-CBC" => (16, 16),
        "AES-192-CBC" => (24, 16),
        "AES-256-CBC" => (32, 16),
        "DES-EDE3-CBC" => (24, 8),
        "DES-CBC" => (8, 8),
        _ => throw new SshException(SshErrorCode.File,
            "Unsupported private key file format"),
    };

    // ── PKCS#8 OIDs (DER content, i.e. without the 0x06 tag byte) ──────────

    // rsaEncryption 1.2.840.113549.1.1.1
    private static ReadOnlySpan<byte> Pkcs8OidRsaEncryption => [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
    // id-ecPublicKey 1.2.840.10045.2.1
    private static ReadOnlySpan<byte> Pkcs8OidEcPublicKey => [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
    // id-Ed25519 1.3.101.112
    private static ReadOnlySpan<byte> Pkcs8OidEd25519 => [0x2B, 0x65, 0x70];
    // pbes2 1.2.840.113549.1.5.13
    private static ReadOnlySpan<byte> Pkcs8OidPbes2 => [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D];
    // pbkdf2 1.2.840.113549.1.5.12
    private static ReadOnlySpan<byte> Pkcs8OidPbkdf2 => [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C];
    // hmacWithSHA1 1.2.840.113549.2.7
    private static ReadOnlySpan<byte> Pkcs8OidHmacWithSha1 => [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x07];
    // hmacWithSHA256 1.2.840.113549.2.9
    private static ReadOnlySpan<byte> Pkcs8OidHmacWithSha256 => [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x09];

    /// <summary>
    /// Maps a PKCS#8 encryptionScheme OID to the cipher name used by
    /// <see cref="CipherKeyIvLengths"/>/<see cref="DecryptTraditionalPem"/>.
    /// Unknown OIDs are OpenSSL's unsupported-encryption failure — the C's
    /// plain FILE error (openssl.c:5043-5047).
    /// </summary>
    private static string Pkcs8CipherFromOid(ReadOnlySpan<byte> oid)
    {
        // aes128-CBC 2.16.840.1.101.3.4.1.2, aes192-CBC …22, aes256-CBC …42
        // (common 8-byte prefix 60 86 48 01 65 03 04 01; final arc selects).
        if (oid.Length == 9 && oid.StartsWith((ReadOnlySpan<byte>)[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01]))
        {
            return oid[^1] switch
            {
                0x02 => "AES-128-CBC",
                0x16 => "AES-192-CBC",
                0x2A => "AES-256-CBC",
                _ => throw new SshException(SshErrorCode.File,
                    "Unsupported private key file format"),
            };
        }

        // des-ede3-cbc 1.2.840.113549.3.7
        if (oid.SequenceEqual((ReadOnlySpan<byte>)[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x07]))
        {
            return "DES-EDE3-CBC";
        }

        throw new SshException(SshErrorCode.File, "Unsupported private key file format");
    }

    /// <summary>
    /// Decrypts a traditional-PEM ciphertext (the WHOLE base64 body — OpenSSL
    /// 3.x writes no salt prefix) with the DEK-Info IV and the
    /// <c>EVP_BytesToKey</c>-derived key. PKCS#7 padding is validated like
    /// the C's default EVP padding: a bad pad throws
    /// <see cref="CryptographicException"/>, which the caller maps to
    /// KEYFILE_AUTH_FAILED (the C's BAD_DECRYPT path, openssl.c:5036-5041).
    /// </summary>
    [SuppressMessage("Security", "CA5351:Do not use insecure cryptographic algorithms", Justification = "DES/3DES are required to decrypt legacy PEM keys (parity with OpenSSL's PEM_read); the caller opted into a legacy key format.")]
    [SuppressMessage("Security", "CA5350:Do not use insecure cryptographic algorithms", Justification = "MD5 is the traditional PEM key derivation (EVP_BytesToKey); parity with OpenSSL's PEM_do_header.")]
    private static byte[] DecryptTraditionalPem(string cipherName, ReadOnlySpan<byte> ciphertext, byte[] key, byte[] iv)
    {
        if (cipherName.StartsWith("AES-", StringComparison.Ordinal))
        {
            using var aes = Aes.Create();
            aes.SetKey(key);
            return aes.DecryptCbc(ciphertext, iv, PaddingMode.PKCS7);
        }

        if (cipherName == "DES-EDE3-CBC")
        {
            using var tdes = TripleDES.Create();
            tdes.SetKey(key);
            return tdes.DecryptCbc(ciphertext, iv, PaddingMode.PKCS7);
        }

        using var des = DES.Create();
        des.SetKey(key);
        return des.DecryptCbc(ciphertext, iv, PaddingMode.PKCS7);
    }

    /// <summary>
    /// Parses an unencrypted PKCS#1 <c>-----BEGIN RSA PRIVATE KEY-----</c>
    /// DER body and returns an <see cref="OpenSshKey"/> carrying the key in
    /// the OpenSSH new-format blobs, so the common
    /// <see cref="SshPemKey.Parse(OpenSshKey)"/> path handles it unchanged.
    /// libssh2 accepts these via <c>PEM_read_bio_PrivateKey</c>
    /// (openssl.c:5016). Errors map to <see cref="SshErrorCode.File"/>
    /// "Unsupported private key file format" — the user-facing libssh2
    /// mapping (openssl.c:5043-5047).
    /// </summary>
    private static OpenSshKey ParseLegacyRsaPrivateKey(ReadOnlySpan<byte> der)
    {
        try
        {
            // PKCS#1 RSAPrivateKey ::= SEQUENCE {
            //   version(0), n, e, d, p, q, exponent1, exponent2, coefficient }
            // (RFC 8017 A.1.2). exponent1/2 are recomputed by SshPemKey/SshSign.
            var outer = new DerReader(der);
            outer.ExpectSequence(out ReadOnlySpan<byte> body);
            var r = new DerReader(body);
            _ = r.ReadInteger();   // version (must be 0; not validated — the C's OpenSSL parse is equally lenient)
            byte[] n = r.ReadInteger();
            byte[] e = r.ReadInteger();
            byte[] d = r.ReadInteger();
            byte[] p = r.ReadInteger();
            byte[] q = r.ReadInteger();
            _ = r.ReadInteger();   // exponent1 (d mod (p-1)) — recomputed
            _ = r.ReadInteger();   // exponent2 (d mod (q-1)) — recomputed
            byte[] coeff = r.ReadInteger();   // coefficient (iqmp — q^-1 mod p)
            // [otherPrimeInfos] (multi-prime RSA) is ignored if present.

            // ssh-rsa public blob: [string "ssh-rsa"][mpint e][mpint n]
            // (RFC 4253 §6.6 — a high-bit n carries the leading 0x00 sign
            // byte, matching ssh-keygen's .pub output).
            byte[] publicBlob = BuildSshRsaPublicBlob(e, n);
            byte[] privateBlob = BuildOpenSshRsaPrivateBlob(n, e, d, coeff, p, q);
            return new OpenSshKey("none", "none", publicBlob, privateBlob, string.Empty);
        }
        catch (SshException)
        {
            throw new SshException(SshErrorCode.File, "Unsupported private key file format");
        }
    }

    /// <summary>
    /// Builds an OpenSSH new-format private key blob (check1‖check2‖keytype‖
    /// fields‖comment) for an RSA key — PROTOCOL.key field order
    /// n, e, d, iqmp, p, q (matching <see cref="SshPemKey"/>'s parser).
    /// </summary>
    private static byte[] BuildOpenSshRsaPrivateBlob(byte[] n, byte[] e, byte[] d, byte[] coeff, byte[] p, byte[] q)
    {
        byte[] check = new byte[4];
        RandomNumberGenerator.Fill(check);

        using var ms = new MemoryStream(512);
        ms.Write(check, 0, 4);          // check1
        ms.Write(check, 0, 4);          // check2 (equal — the parser only compares)
        WriteSshString(ms, "ssh-rsa"u8);
        WriteSshMpint(ms, n);
        WriteSshMpint(ms, e);
        WriteSshMpint(ms, d);
        WriteSshMpint(ms, coeff);
        WriteSshMpint(ms, p);
        WriteSshMpint(ms, q);
        WriteSshString(ms, []);          // empty comment
        return ms.ToArray();
    }

    /// <summary>
    /// Builds an ssh-rsa public key blob: <c>[string "ssh-rsa"][mpint e][mpint n]</c>
    /// (RFC 4253 §6.6 — e and n are mpints, so a high-bit n carries the
    /// leading 0x00 sign byte, byte-identical to ssh-keygen's .pub output).
    /// </summary>
    private static byte[] BuildSshRsaPublicBlob(byte[] e, byte[] n)
    {
        using var ms = new MemoryStream(512);
        WriteSshString(ms, "ssh-rsa"u8);
        WriteSshMpint(ms, e);
        WriteSshMpint(ms, n);
        return ms.ToArray();
    }

    private static void WriteSshString(Stream ms, ReadOnlySpan<byte> value)
    {
        Span<byte> len = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(len, value.Length);
        ms.Write(len);
        ms.Write(value);
    }

    private static void WriteSshMpint(Stream ms, byte[] valueBE)
    {
        byte[] buf = new byte[4 + Endian.GetMpintLength(valueBE)];
        Endian.WriteMpint(buf, valueBE);
        ms.Write(buf);
    }

    /// <summary>
    /// Minimal DER reader (SEQUENCE, INTEGER, OCTET STRING, OID) for the
    /// PKCS#1/PKCS#8 structures. Throws <see cref="SshErrorCode.Proto"/> on
    /// malformed input.
    /// </summary>
    private ref struct DerReader
    {
        private ReadOnlySpan<byte> _data;

        public DerReader(ReadOnlySpan<byte> data) => _data = data;

        /// <summary>True when all input has been consumed.</summary>
        public readonly bool AtEnd => _data.IsEmpty;

        /// <summary>The tag byte of the next element (caller checks <see cref="AtEnd"/>).</summary>
        public readonly byte PeekTag() => _data[0];

        public void ExpectSequence(out ReadOnlySpan<byte> body)
        {
            if (_data.Length < 2 || _data[0] != 0x30)
            {
                throw new SshException(SshErrorCode.Proto, "Invalid legacy RSA private key (DER)");
            }

            int len = ReadLength(1, out int lengthBytes);
            int contentStart = 1 + lengthBytes;
            if (contentStart + len > _data.Length)
            {
                throw new SshException(SshErrorCode.Proto, "Invalid legacy RSA private key (DER)");
            }

            body = _data.Slice(contentStart, len);
            _data = _data.Slice(contentStart + len);
        }

        /// <summary>Reads a positive INTEGER, stripping the DER sign byte.</summary>
        public byte[] ReadInteger()
        {
            if (_data.Length < 2 || _data[0] != 0x02)
            {
                throw new SshException(SshErrorCode.Proto, "Invalid legacy RSA private key (DER)");
            }

            ReadOnlySpan<byte> value = ReadContent(0x02);

            // Positive values may carry a leading 0x00 sign byte.
            if (value.Length > 0 && value[0] == 0)
            {
                value = value[1..];
            }

            return value.ToArray();
        }

        /// <summary>Reads an OCTET STRING (tag 0x04), returning its content.</summary>
        public ReadOnlySpan<byte> ReadOctetString() => ReadContent(0x04);

        /// <summary>Reads an OBJECT IDENTIFIER (tag 0x06), returning its DER content.</summary>
        public ReadOnlySpan<byte> ReadOid() => ReadContent(0x06);

        /// <summary>
        /// Reads a context-specific constructed element (e.g. SEC1's
        /// <c>[0]</c>/<c>[1]</c>, tags 0xA0/0xA1), returning its content.
        /// </summary>
        public ReadOnlySpan<byte> ReadTagged(byte tag) => ReadContent(tag);

        /// <summary>Skips the next element entirely (e.g. rsaEncryption's NULL params).</summary>
        public void SkipElement()
        {
            if (_data.Length < 2)
            {
                throw new SshException(SshErrorCode.Proto, "Invalid legacy RSA private key (DER)");
            }

            int len = ReadLength(1, out int lengthBytes);
            int contentStart = 1 + lengthBytes;
            if (contentStart + len > _data.Length)
            {
                throw new SshException(SshErrorCode.Proto, "Invalid legacy RSA private key (DER)");
            }

            _data = _data.Slice(contentStart + len);
        }

        /// <summary>
        /// Reads the content of the next element with tag <paramref name="tag"/>
        /// and advances past it.
        /// </summary>
        private ReadOnlySpan<byte> ReadContent(byte tag)
        {
            if (_data.Length < 2 || _data[0] != tag)
            {
                throw new SshException(SshErrorCode.Proto, "Invalid legacy RSA private key (DER)");
            }

            int len = ReadLength(1, out int lengthBytes);
            int contentStart = 1 + lengthBytes;
            if (contentStart + len > _data.Length)
            {
                throw new SshException(SshErrorCode.Proto, "Invalid legacy RSA private key (DER)");
            }

            ReadOnlySpan<byte> content = _data.Slice(contentStart, len);
            _data = _data.Slice(contentStart + len);
            return content;
        }

        /// <summary>
        /// Reads a DER length at <paramref name="offset"/> (short or long
        /// form) and reports how many bytes the length encoding occupied.
        /// </summary>
        private readonly int ReadLength(int offset, out int lengthBytes)
        {
            if (offset >= _data.Length)
            {
                throw new SshException(SshErrorCode.Proto, "Invalid legacy RSA private key (DER)");
            }

            byte first = _data[offset];
            if ((first & 0x80) == 0)
            {
                lengthBytes = 1;
                return first;   // short form
            }

            int count = first & 0x7F;
            if (count == 0 || count > 4 || offset + 1 + count > _data.Length)
            {
                throw new SshException(SshErrorCode.Proto, "Invalid legacy RSA private key (DER)");
            }

            int len = 0;
            for (int i = 0; i < count; i++)
            {
                len = (len << 8) | _data[offset + 1 + i];
            }

            lengthBytes = 1 + count;
            return len;
        }
    }
}
