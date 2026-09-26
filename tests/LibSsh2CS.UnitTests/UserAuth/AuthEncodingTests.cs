using System.Buffers.Binary;
using System.Text;

namespace LibSsh2CS.UnitTests.UserAuth;

public class AuthEncodingTests
{
    [Theory]
    [InlineData("empty")]
    [InlineData("ascii")]
    [InlineData("unicode")]
    [InlineData("fallback")]
    [InlineData("long")]
    public void Builders_PreserveWireEncodingAndIndependentResults(string kind)
    {
        string text = kind switch
        {
            "empty" => string.Empty,
            "unicode" => "用户 🌍 密码",
            "fallback" => "bad\ud800text\udc00",
            "long" => new string('x', 4096),
            _ => "alice-password",
        };
        byte[] key = [1, 2, 3, 4];
        byte[] keyCopy = (byte[])key.Clone();
        byte[] extra = [9, 8];
        string[] answers = [text, "second", string.Empty];

        Check(() => SshUserAuth.BuildUserauthRequest(text, "none", extra),
            Packet(50, text, "ssh-connection", "none").Concat(extra).ToArray());
        Check(() => SshUserAuth.BuildPasswordRequest(text, text, false, null),
            Packet(50, text, "ssh-connection", "password", (byte)0, text));
        Check(() => SshUserAuth.BuildPasswordRequest(text, text, true, "old"),
            Packet(50, text, "ssh-connection", "password", (byte)1, "old", text));
        Check(() => SshUserAuth.BuildPublickeyProbe(text, "ssh-ed25519", key),
            Packet(50, text, "ssh-connection", "publickey", (byte)0, "ssh-ed25519", key));
        Check(() => SshUserAuth.BuildKbdIntRequest(text),
            Packet(50, text, "ssh-connection", "keyboard-interactive", "", ""));
        Check(() => SshUserAuth.BuildKbdIntResponse(answers), Packet(61, 3u, text, "second", ""));
        Check(() => SshUserAuth.BuildKbdIntResponse([]), Packet(61, 0u));
        Check(() => SshUserAuth.BuildHostbasedRequest(text, "ssh-ed25519", key, text, "local"),
            Packet(50, text, "ssh-connection", "hostbased", "ssh-ed25519", key, text, "local"));
        Assert.Equal(keyCopy, key);
        Assert.Equal(new byte[] { 9, 8 }, extra);
        Assert.Equal(new[] { text, "second", string.Empty }, answers);
    }

    private static void Check(Func<byte[]> build, byte[] expected)
    {
        byte[] first = build();
        Assert.Equal(expected, first);
        byte[] second = build();
        Assert.NotSame(first, second);
        first[0] ^= 255;
        Assert.Equal(expected, second);
    }

    // Independent reference encoder: streaming fields rather than precomputing payload offsets.
    private static byte[] Packet(byte type, params object[] fields)
    {
        using var stream = new MemoryStream();
        stream.WriteByte(type);
        Span<byte> length = stackalloc byte[4];
        foreach (object field in fields)
        {
            if (field is byte flag)
            {
                stream.WriteByte(flag);
            }
            else if (field is uint count)
            {
                BinaryPrimitives.WriteUInt32BigEndian(length, count);
                stream.Write(length);
            }
            else
            {
                byte[] bytes = field is string text ? Encoding.UTF8.GetBytes(text) : (byte[])field;
                BinaryPrimitives.WriteInt32BigEndian(length, bytes.Length);
                stream.Write(length);
                stream.Write(bytes);
            }
        }
        return stream.ToArray();
    }
}
