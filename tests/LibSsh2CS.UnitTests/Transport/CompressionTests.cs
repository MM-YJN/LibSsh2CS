using LibSsh2CS.Transport;

namespace LibSsh2CS.UnitTests.Transport;

/// <summary>
/// Tests for the Phase 1 increment-4 compression adapters: registry, metadata
/// parity with <c>comp.c</c>, the <c>none</c> passthrough, and zlib (RFC 1950)
/// round-trip including cross-packet dictionary persistence.
/// </summary>
public class CompressionTests
{
    // ── Registry ──────────────────────────────────────────────────────

    [Fact]
    public void DefaultPreferences_HasInScopeAlgorithms_InPreferenceOrder()
    {
        // Order mirrors comp_methods[] (comp.c:359).
        Assert.Equal(new[] { "zlib", "zlib@openssh.com", "none" }, CompressionMethods.DefaultPreferences);
    }

    [Theory]
    [InlineData("zlib", true, true)]
    [InlineData("zlib@openssh.com", true, false)]
    [InlineData("none", false, false)]
    public void Metadata_MatchesLibssh2(string name, bool compresses, bool useInAuth)
    {
        // use_in_auth: zlib=1 (compress during auth); zlib@openssh.com=0 (delayed).
        using ICompression comp = CompressionMethods.Create(name)!;
        Assert.Equal(name, comp.Name);
        Assert.Equal(compresses, comp.Compresses);
        Assert.Equal(useInAuth, comp.UseInAuth);
    }

    [Fact]
    public void Create_UnknownName_ReturnsNull()
    {
        Assert.Null(CompressionMethods.Create("bzip2"));
    }

    // ── none ──────────────────────────────────────────────────────────

    [Fact]
    public void None_PassesDataThroughUnchanged()
    {
        using var comp = new NoneCompression();
        comp.Init(compress: true);
        byte[] data = { 1, 2, 3, 4, 5 };
        Assert.Equal(data, comp.Compress(data));
        Assert.Equal(data, comp.Decompress(data));
    }

    // ── zlib round-trip ───────────────────────────────────────────────

    [Fact]
    public void Zlib_RoundTrips_SinglePacket()
    {
        byte[] payload = MakeText(200);
        using var comp = new ZlibCompression("zlib", useInAuth: true);
        using var dec = new ZlibCompression("zlib", useInAuth: true);
        comp.Init(compress: true);
        dec.Init(compress: false);

        byte[] compressed = comp.Compress(payload);
        byte[] restored = dec.Decompress(compressed);
        Assert.Equal(payload, restored);
    }

    [Fact]
    public void Zlib_FirstPacketBeginsWithZlibHeader_0x78()
    {
        // RFC 1950 zlib format: the first byte of the first packet is 0x78
        // (deflate, window=32K). Raw deflate (DeflateEncoder) would emit no such
        // header — this guards the ZLibEncoder-vs-DeflateEncoder choice.
        using var comp = new ZlibCompression("zlib", useInAuth: true);
        comp.Init(compress: true);

        byte[] compressed = comp.Compress(MakeText(100));
        Assert.NotEmpty(compressed);
        Assert.Equal(0x78, compressed[0]);
    }

    [Fact]
    public void Zlib_DictionaryPersistsAcrossPackets()
    {
        // Each packet is a flush unit: compress p1,p2,p3 on one instance, then
        // decompress each chunk on one instance and expect p1,p2,p3 back in order
        // — only possible if the dictionary carries across packets on both sides.
        byte[] p1 = MakeText(300);
        byte[] p2 = MakeText(300);
        byte[] p3 = MakeText(300);

        using var comp = new ZlibCompression("zlib", useInAuth: true);
        using var dec = new ZlibCompression("zlib", useInAuth: true);
        comp.Init(compress: true);
        dec.Init(compress: false);

        byte[] c1 = comp.Compress(p1);
        byte[] c2 = comp.Compress(p2);
        byte[] c3 = comp.Compress(p3);

        Assert.Equal(p1, dec.Decompress(c1));
        Assert.Equal(p2, dec.Decompress(c2));
        Assert.Equal(p3, dec.Decompress(c3));
    }

    [Fact]
    public void Zlib_RoundTripsHighEntropyData()
    {
        // Incompressible random data must still round-trip (zlib stores it ~verbatim).
        byte[] payload = new byte[512];
        new Random(2024).NextBytes(payload);

        using var comp = new ZlibCompression("zlib@openssh.com", useInAuth: false);
        using var dec = new ZlibCompression("zlib@openssh.com", useInAuth: false);
        comp.Init(compress: true);
        dec.Init(compress: false);

        byte[] compressed = comp.Compress(payload);
        Assert.Equal(payload, dec.Decompress(compressed));
    }

    [Fact]
    public void Zlib_CompressBeforeInit_Throws()
    {
        using var comp = new ZlibCompression("zlib", useInAuth: true);
        Assert.Throws<InvalidOperationException>(() => comp.Compress(new byte[10]));
    }

    private static byte[] MakeText(int length)
    {
        // Highly compressible repeated text — exercises actual compression.
        const string Phrase = "the quick brown fox jumps over the lazy dog ";
        byte[] phrase = System.Text.Encoding.ASCII.GetBytes(Phrase);
        byte[] result = new byte[length];
        for (int i = 0; i < length; i++)
        {
            result[i] = phrase[i % phrase.Length];
        }

        return result;
    }
}
