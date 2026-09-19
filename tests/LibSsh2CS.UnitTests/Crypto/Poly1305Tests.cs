using LibSsh2CS.Crypto;

namespace LibSsh2CS.UnitTests.Crypto;

/// <summary>
/// Poly1305 known-answer tests. Poly1305 is nonce-independent, so the primary
/// vector is RFC 8439 §2.5.2 (canonical). The empty / 16-byte / 17-byte cases
/// were captured from the upstream <c>poly1305.c</c> to exercise the partial-block
/// padding path (0x01 pad byte) and the exactly-one-full-block path.
/// </summary>
public class Poly1305Tests
{
    // RFC 8439 §2.5.2 key: r = 85d6be7857556d337f4452fe42d506a8,
    // s = 01038008afb0db2fd4abff6af4149f51b. Note the empty-message tag equals s
    // (h stays zero), which is a useful sanity check on the finish step.
    private const string KeyHex =
        "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b";

    private static byte[] Key() => Convert.FromHexString(KeyHex);

    [Fact]
    public void Auth_Rfc8439_2_5_2_Matches()
    {
        byte[] message = System.Text.Encoding.ASCII.GetBytes("Cryptographic Forum Research Group");
        byte[] tag = new byte[16];
        Poly1305.Auth(tag, message, Key());
        Assert.Equal(Convert.FromHexString("a8061dc1305136c6c22b8baf0c0127a9"), tag);
    }

    [Fact]
    public void Auth_EmptyMessage_MatchesGolden()
    {
        // Empty message: h = 0, so the tag is just s (key[16..32]). Covers the
        // zero-iteration straight-to-finish path.
        byte[] tag = new byte[16];
        Poly1305.Auth(tag, Array.Empty<byte>(), Key());
        Assert.Equal(Convert.FromHexString("0103808afb0db2fd4abff6af4149f51b"), tag);
    }

    [Fact]
    public void Auth_Exactly16Bytes_MatchesGolden()
    {
        // One full block only (no partial padding block).
        byte[] message = System.Text.Encoding.ASCII.GetBytes("0123456789abcdef");
        byte[] tag = new byte[16];
        Poly1305.Auth(tag, message, Key());
        Assert.Equal(Convert.FromHexString("2a522975c7f018fce2b3f18e48176d91"), tag);
    }

    [Fact]
    public void Auth_17Bytes_MatchesGolden()
    {
        // One full block + a single-byte partial block (exercises the 0x01 pad and
        // the final multiply path).
        byte[] message = System.Text.Encoding.ASCII.GetBytes("0123456789abcdefg");
        byte[] tag = new byte[16];
        Poly1305.Auth(tag, message, Key());
        Assert.Equal(Convert.FromHexString("8a8887c681dfebbe61473bfa9b30592a"), tag);
    }

    [Fact]
    public void Auth_RejectsBadKeyLength()
    {
        Assert.Throws<ArgumentException>(() =>
        {
            Span<byte> tag = stackalloc byte[16];
            Poly1305.Auth(tag, Array.Empty<byte>(), new byte[31]);
        });
    }

    [Fact]
    public void Auth_RejectsUndersizedTagBuffer()
    {
        Assert.Throws<ArgumentException>(() =>
        {
            Span<byte> tag = stackalloc byte[15];
            Poly1305.Auth(tag, Array.Empty<byte>(), Key());
        });
    }
}
