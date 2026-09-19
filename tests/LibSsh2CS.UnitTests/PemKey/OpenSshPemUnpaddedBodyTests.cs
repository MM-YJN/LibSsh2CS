using System.Text;

namespace LibSsh2CS.UnitTests.PemKey;

/// <summary>
/// Regression tests for the OpenSSH PEM decode-buffer sizing: the
/// parse buffer must be sized from the base64 body length, not
/// <c>Base64.GetMaxDecodedLength</c> (3·⌊L/4⌋ — the BCL strict decoder's
/// floor bound), because <see cref="SshPemParser"/> decodes with the libssh2
/// lenient decoder (<c>misc.c:396-424</c>), which accepts unpadded tails and
/// writes partial trailing groups — up to 2 bytes beyond the floor bound.
/// </summary>
public class OpenSshPemUnpaddedBodyTests
{
    /// <summary>
    /// A base64 body with an unpadded partial tail must decode inside the
    /// allocated buffer and fail cleanly at the key-content validation, not
    /// with an out-of-bounds write. These lengths are the worst cases
    /// reachable through the armor (the END-marker rule forces a trailing
    /// newline, so the body is N valid chars + 1 junk byte): 342 valid
    /// sextets put the decoder's last write at index 256, 1366 at index 1024.
    /// Sizing the buffer from <c>Base64.GetMaxDecodedLength</c> (3·⌊L/4⌋ —
    /// the BCL strict decoder's floor bound) leaves those writes 1 byte past
    /// the 256-byte <c>stackalloc</c> / 1024-byte pool bucket. The current
    /// runtime's <c>GetMaxByteCount(0) = 3</c> passphrase slack happens to
    /// mask the overrun (255+3 &gt; 256 forces the pool path); this test pins
    /// the sizing rule (buffer ≥ body length) so the partial-tail write can
    /// never reach the boundary even if that slack changes.
    /// </summary>
    [Theory]
    [InlineData(342)]   // pre-fix bound 3·⌊343/4⌋ = 255 → last write at index 256
    [InlineData(1366)]  // pre-fix bound 3·⌊1367/4⌋ = 1023 → last write at index 1024
    public void ParseOpenSshPrivateKey_UnpaddedPartialTailBody_ThrowsCleanSshException(int validChars)
    {
        // Body = N valid chars plus the armor-required line terminator (junk,
        // skipped by the lenient decoder): b64.Length = N + 1, N valid
        // sextets with N ≡ 2 (mod 4). 'A' decodes to zero, so the decoded
        // data is all zeros.
        string body = new string('A', validChars) + "\n";
        string pem = "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            + body
            + "-----END OPENSSH PRIVATE KEY-----";

        // The auth-magic check fails on the all-zero decoded data. A clean
        // Proto proves the decode stayed in bounds.
        SshException ex = Assert.Throws<SshException>(() =>
            SshPemParser.ParseOpenSshPrivateKey(Encoding.ASCII.GetBytes(pem), passphrase: null));

        Assert.Equal(SshErrorCode.Proto, ex.ErrorCode);
    }
}
