using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;

namespace LibSsh2CS.Transport;

/// <summary>
/// Diffie-Hellman group14 key exchange (RFC 4253 §8.2, group = RFC 3526 §3
/// "modp2048", g = 2, 2048-bit prime). Used by the
/// <c>diffie-hellman-group14-sha1</c> and <c>diffie-hellman-group14-sha256</c>
/// KEX methods.
/// </summary>
/// <remarks>
/// <para>
/// libssh2 C source: <c>kex.c</c> <c>kex_method_diffie_hellman_group14_key_exchange</c>
/// (the 256-byte <c>p_value</c> and g = 2) plus the OpenSSL backend
/// <c>_libssh2_dh_init</c> / <c>_libssh2_dh_key_pair</c> / <c>_libssh2_dh_secret</c>.
/// The backend abstraction collapses to <see cref="BigInteger.ModPow"/> here.
/// </para>
/// <para>
/// <b>Private exponent range (parity note).</b> The reference samples
/// <c>x = BN_rand(group_order*8 - 1 = 2047, top = 0, bottom = -1)</c> — i.e. a
/// 2047-bit number with the top bit set and the low bit set (odd). See
/// <c>openssl.c</c> <c>_libssh2_dh_key_pair</c>. <see cref="DhGroup14()"/>
/// reproduces this so the generated public value has the same distribution as a
/// libssh2/OpenSSL client.
/// </para>
/// <para>
/// This class returns <see cref="BigInteger"/> values (e, K). The SSH mpint
/// wire encoding (leading-zero rule, <c>kex.c</c> lines 608-638) is handled
/// later by the KEX layer via <c>Util/Endian.cs</c>; it is intentionally not
/// done here.
/// </para>
/// </remarks>
internal sealed class DhGroup14
{
    /// <summary>The RFC 3526 §3 modp2048 prime modulus bit count.</summary>
    public const int GroupBits = 2048;

    /// <summary>
    /// The private exponent bit length sampled by the reference
    /// (<c>group_order * 8 - 1</c> with <c>top = 0</c>).
    /// </summary>
    public const int PrivateBits = GroupBits - 1;

    private const int Generator = 2;
    private const int PrimeByteLength = 256;

    // RFC 3526 §3 modp2048 prime (256 bytes), byte-exact with kex.c p_value[].
    // The leading "0" forces BigInteger.Parse to treat the value as POSITIVE:
    // the prime's high bit is set (0xFF…), and NumberStyles.HexNumber parsing
    // is two's-complement — without the guard digit the result would be
    // negative, silently corrupting every ModPow (e, K) computation.
    private static readonly BigInteger s_prime = BigInteger.Parse(
        "0" +
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" +
        "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" +
        "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05" +
        "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB" +
        "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
        "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);

    private readonly BigInteger _privateValue;

    /// <summary>
    /// Initializes a new DH group14 keypair with a fresh random private exponent
    /// (2047-bit, top-bit-set, odd — matching the OpenSSL reference sampling).
    /// </summary>
    public DhGroup14()
        : this(GeneratePrivateValue())
    {
    }

    /// <summary>
    /// Initializes a new keypair from a known private exponent. Intended for
    /// deterministic tests; production callers use <see cref="DhGroup14()"/>.
    /// </summary>
    internal DhGroup14(BigInteger privateValue)
    {
        _privateValue = privateValue;
        PublicKey = BigInteger.ModPow(Generator, privateValue, s_prime);
    }

    /// <summary>
    /// The client public value <c>e = g^x mod p</c>, to be sent in
    /// SSH_MSG_KEXDH_INIT.
    /// </summary>
    public BigInteger PublicKey { get; }

    /// <summary>
    /// Computes the shared secret <c>K = f^x mod p</c> from the server's public
    /// value <paramref name="serverPublic"/> (<c>f</c>).
    /// </summary>
    public BigInteger ComputeSharedSecret(BigInteger serverPublic)
    {
        if (serverPublic <= BigInteger.One || serverPublic >= s_prime - BigInteger.One)
        {
            throw new SshException(SshErrorCode.KeyExchangeFailure, "Invalid DH server public value.");
        }

        return BigInteger.ModPow(serverPublic, _privateValue, s_prime);
    }

    /// <summary>The private exponent, exposed for range/format assertions in tests.</summary>
    internal BigInteger TestPrivateValue => _privateValue;

    /// <summary>
    /// Samples a 2047-bit private exponent with the top bit set and the low bit
    /// set (odd), mirroring OpenSSL <c>BNrand(2047, top=0, bottom=-1)</c> as
    /// called from <c>_libssh2_dh_key_pair</c>.
    /// </summary>
    internal static BigInteger GeneratePrivateValue()
    {
        Span<byte> raw = stackalloc byte[PrimeByteLength];
        RandomNumberGenerator.Fill(raw);

        // 256 bytes span bits 0..2047 (bit 2047 = byte[0] high bit). Force:
        //   bit 2047 = 0  (so the value is strictly < 2^2047)
        //   bit 2046 = 1  (top bit set → exactly a 2047-bit number)
        // i.e. byte[0] = (raw & 0x3F) | 0x40.
        raw[0] = (byte)((raw[0] & 0x3F) | 0x40);

        // bottom set → odd (BN_rand bottom != 0).
        raw[PrimeByteLength - 1] |= 0x01;

        return FromBigEndian(raw);
    }

    // Decodes a big-endian unsigned byte string to BigInteger. Reverses to the
    // little-endian form the constructor expects and appends a zero high byte so
    // two's-complement decoding stays non-negative (same trick as
    // Fe25519Ops.FromBytes uses internally).
    private static BigInteger FromBigEndian(ReadOnlySpan<byte> bigEndian)
    {
        byte[] littleEndian = new byte[bigEndian.Length + 1];
        for (int i = 0; i < bigEndian.Length; i++)
        {
            littleEndian[i] = bigEndian[bigEndian.Length - 1 - i];
        }

        // littleEndian[bigEndian.Length] is already 0 (positive sign byte).
        return new BigInteger(littleEndian);
    }
}
