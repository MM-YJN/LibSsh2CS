using System.Buffers.Binary;
using System.Text;

using LibSsh2CS.Util;

namespace LibSsh2CS.UnitTests.UserAuth;

/// <summary>
/// INFO_REQUEST payload parsing — parity with libssh2's
/// <c>userauth_keyboard_interactive_decode_info_request</c>
/// (userauth_kbd_packet.c:43-152): string under-reads → ALLOC (the C's
/// <c>_libssh2_copy_string</c> failure), u32/boolean under-reads and the
/// &lt;17 gate → BUFFER_TOO_SMALL, &gt;100 prompts → OUT_OF_BOUNDARY.
/// </summary>
public class KbdIntInfoRequestTests
{
    [Fact]
    public void Parse_ValidPayload_ReturnsFieldsAndPrompts()
    {
        byte[] payload = BuildInfoRequest(
            name: "Password authentication",
            instruction: "Please enter your password.",
            language: "en-US",
            prompts: [("Password: ", Echo: false), ("PIN: ", Echo: true)]);

        SshKbdInfoRequest info = SshUserAuth.ParseInfoRequestPayload(payload);

        Assert.Equal("Password authentication", info.Name);
        Assert.Equal("Please enter your password.", info.Instruction);
        Assert.Equal(2, info.Prompts.Length);
        Assert.Equal("Password: ", info.Prompts[0].Text);
        Assert.False(info.Prompts[0].Echo);
        Assert.Equal("PIN: ", info.Prompts[1].Text);
        Assert.True(info.Prompts[1].Echo);
    }

    [Fact]
    public void Parse_ZeroPrompts_ReturnsEmptyPrompts()
    {
        // The C returns early with no prompt array (userauth_kbd_packet.c:116-118).
        byte[] payload = BuildInfoRequest("n", "i", "l", []);

        SshKbdInfoRequest info = SshUserAuth.ParseInfoRequestPayload(payload);

        Assert.Empty(info.Prompts);
    }

    [Fact]
    public void Parse_PayloadShorterThan17_ThrowsBufferTooSmall()
    {
        // The C's minimum-length gate (userauth_kbd_packet.c:57-62).
        byte[] payload = [60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        SshException ex = Assert.Throws<SshException>(() => SshUserAuth.ParseInfoRequestPayload(payload));

        Assert.Equal(SshErrorCode.BufferTooSmall, ex.ErrorCode);
        Assert.Contains("keyboard data buffer too small", ex.Message);
    }

    [Fact]
    public void Parse_TruncatedName_ThrowsAlloc()
    {
        // Declared name length (100) exceeds the remaining bytes — the C's
        // copy failure is reported as ALLOC (userauth_kbd_packet.c:65-69).
        // Total length must stay ≥ 17 to pass the minimum-length gate first.
        byte[] payload = [60, .. Hdr(100), .. Enumerable.Repeat((byte)'x', 16)];

        SshException ex = Assert.Throws<SshException>(() => SshUserAuth.ParseInfoRequestPayload(payload));

        Assert.Equal(SshErrorCode.Alloc, ex.ErrorCode);
        Assert.Contains("'name' request field", ex.Message);
    }

    [Fact]
    public void Parse_TruncatedInstruction_ThrowsAlloc()
    {
        byte[] payload = [60, .. Str("ok"), .. Hdr(100), .. "short"u8, .. Str("lang"), .. U32(0)];

        SshException ex = Assert.Throws<SshException>(() => SshUserAuth.ParseInfoRequestPayload(payload));

        Assert.Equal(SshErrorCode.Alloc, ex.ErrorCode);
        Assert.Contains("'instruction' request field", ex.Message);
    }

    [Fact]
    public void Parse_TruncatedLanguageTag_ThrowsAlloc()
    {
        byte[] payload = [60, .. Str("ok"), .. Str("ok"), .. Hdr(100), .. "short"u8];

        SshException ex = Assert.Throws<SshException>(() => SshUserAuth.ParseInfoRequestPayload(payload));

        Assert.Equal(SshErrorCode.Alloc, ex.ErrorCode);
        Assert.Contains("'language tag' request field", ex.Message);
    }

    [Fact]
    public void Parse_TruncatedNumPrompts_ThrowsBufferTooSmall()
    {
        // Only 2 of the 4 u32 bytes present (userauth_kbd_packet.c:119-124).
        byte[] payload = [60, .. Str("n"), .. Str("i"), .. Str("l"), 0, 0];

        SshException ex = Assert.Throws<SshException>(() => SshUserAuth.ParseInfoRequestPayload(payload));

        Assert.Equal(SshErrorCode.BufferTooSmall, ex.ErrorCode);
        Assert.Contains("number of keyboard prompts", ex.Message);
    }

    [Fact]
    public void Parse_TooManyPrompts_ThrowsOutOfBoundary()
    {
        byte[] payload = BuildInfoRequest("n", "i", "l", []);
        // Rewrite the num-prompts field (last 4 bytes) to 101.
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(payload.Length - 4), 101);

        SshException ex = Assert.Throws<SshException>(() => SshUserAuth.ParseInfoRequestPayload(payload));

        Assert.Equal(SshErrorCode.OutOfBoundary, ex.ErrorCode);
        Assert.Contains("too many prompts", ex.Message);
    }

    [Fact]
    public void Parse_TruncatedPromptText_ThrowsAlloc()
    {
        // Declared prompt length (100) exceeds the remaining bytes.
        byte[] payload = [60, .. Str("n"), .. Str("i"), .. Str("l"), .. U32(1), .. Hdr(100), .. "prompt"u8];

        SshException ex = Assert.Throws<SshException>(() => SshUserAuth.ParseInfoRequestPayload(payload));

        Assert.Equal(SshErrorCode.Alloc, ex.ErrorCode);
        Assert.Contains("prompt message", ex.Message);
    }

    [Fact]
    public void Parse_MissingEchoByte_ThrowsBufferTooSmall()
    {
        // Prompt text present, but the echo boolean is missing
        // (userauth_kbd_packet.c:141-146).
        byte[] payload = [60, .. Str("n"), .. Str("i"), .. Str("l"), .. U32(1), .. Str("prompt")];

        SshException ex = Assert.Throws<SshException>(() => SshUserAuth.ParseInfoRequestPayload(payload));

        Assert.Equal(SshErrorCode.BufferTooSmall, ex.ErrorCode);
        Assert.Contains("prompt echo", ex.Message);
    }

    /// <summary>Builds an INFO_REQUEST payload: [60][name][instruction][lang][count][(prompt,echo)]*.</summary>
    private static byte[] BuildInfoRequest(string name, string instruction, string language, (string Text, bool Echo)[] prompts)
    {
        using var ms = new MemoryStream();
        ms.WriteByte(60);
        WriteStr(ms, name);
        WriteStr(ms, instruction);
        WriteStr(ms, language);
        ms.Write(U32((uint)prompts.Length));
        foreach ((string text, bool echo) in prompts)
        {
            WriteStr(ms, text);
            ms.WriteByte(echo ? (byte)1 : (byte)0);
        }

        return ms.ToArray();
    }

    private static void WriteStr(Stream ms, string value)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value);
        ms.Write(U32((uint)bytes.Length));
        ms.Write(bytes);
    }

    private static byte[] Str(string value)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value);
        return [.. U32((uint)bytes.Length), .. bytes];
    }

    /// <summary>A string length prefix declaring <paramref name="length"/> bytes (no content).</summary>
    private static byte[] Hdr(uint length) => U32(length);

    private static byte[] U32(uint value)
    {
        byte[] buf = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(buf, value);
        return buf;
    }
}
