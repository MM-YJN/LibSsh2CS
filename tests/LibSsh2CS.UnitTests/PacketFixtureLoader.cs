using System.Reflection;
using System.Text.Json;

namespace LibSsh2CS.UnitTests;

/// <summary>
/// In-memory representation of one captured framing-mode fixture set (see
/// <c>Fixtures/packet/&lt;mode&gt;/</c> and <c>Capture/capture-packets.py</c>).
/// Holds the 6 RFC 4253 derived keys (A-F) and the per-packet
/// plaintext/ciphertext pairs the oracle committed.
/// </summary>
internal sealed class PacketFixture
{
    /// <summary>
    /// The negotiated algorithm names, from <c>meta.json</c>.
    /// </summary>
    public string NegotiatedCipher { get; set; } = "";
    public string NegotiatedMac { get; set; } = "";
    public string NegotiatedKex { get; set; } = "";
    public string NegotiatedHostkey { get; set; } = "";

    /// <summary>
    /// True if the negotiated cipher is an AEAD cipher (AES-GCM or
    /// ChaCha20-Poly1305) — the MAC is integrated (no separate MAC key used).
    /// </summary>
    public bool IsAead { get; set; }

    /// <summary>
    /// The 6 derived keys by RFC 4253 letter (A=IV-local, B=IV-remote,
    /// C=enc-local, D=enc-remote, E=mac-local, F=mac-remote). Missing for
    /// modes that don't derive that key (e.g. A/B for AEAD ciphers with IvLen=0).
    /// </summary>
    public Dictionary<string, byte[]> Keys { get; set; } = new();

    /// <summary>The per-packet plaintext/ciphertext pairs (outbound, post-NEWKEYS).</summary>
    public List<PacketEntry> Packets { get; set; } = new();
}

internal sealed class PacketEntry
{
    public byte[] Plaintext { get; set; } = Array.Empty<byte>();
    public byte[] Ciphertext { get; set; } = Array.Empty<byte>();
    public int TypeByte { get; set; }
}

/// <summary>
/// Loads a <see cref="PacketFixture"/> from the embedded resources under
/// <c>Fixtures/packet/&lt;mode&gt;/</c>. Applies the MSBuild folder-name hyphen→
/// underscore rewrite so <c>aes256-ctr_std</c> maps to the
/// embedded resource prefix <c>aes256_ctr_std</c>.
/// </summary>
internal static class PacketFixtureLoader
{
    /// <summary>
    /// Loads the fixture for the given friendly mode name (e.g.
    /// <c>aes256-ctr_std</c>, <c>chacha20-poly1305</c>).
    /// </summary>
    public static PacketFixture Load(string mode)
    {
        // MSBuild rewrites hyphens in fixture FOLDER names to underscores.
        string resMode = mode.Replace('-', '_');
        string prefix = $"LibSsh2CS.UnitTests.Fixtures.packet.{resMode}.";

        // key.txt — one "letter hex" line per derived key.
        var fx = new PacketFixture();
        string keyText = LoadText(prefix + "key.txt");
        foreach (string line in keyText.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            string[] parts = line.Trim().Split(' ', 2);
            if (parts.Length == 2)
            {
                fx.Keys[parts[0]] = Convert.FromHexString(parts[1]);
            }
        }

        // meta.json — negotiated algorithms + per-packet index.
        string metaJson = LoadText(prefix + "meta.json");
        using var doc = JsonDocument.Parse(metaJson);
        JsonElement root = doc.RootElement;
        JsonElement neg = root.GetProperty("negotiated");
        fx.NegotiatedKex = neg.GetProperty("kex").GetString() ?? "";
        fx.NegotiatedCipher = neg.GetProperty("crypt").GetString() ?? "";
        fx.NegotiatedMac = neg.GetProperty("mac").GetString() ?? "";
        fx.NegotiatedHostkey = neg.GetProperty("hostkey").GetString() ?? "";
        // AEAD detection: the cipher name tells us.
        string c = fx.NegotiatedCipher;
        fx.IsAead = c.Contains("gcm") || c.Contains("chacha20-poly1305");

        // Per-packet files: pkt_<n>_out.pt + pkt_<n>_out.ct.
        foreach (JsonElement p in root.GetProperty("packets").EnumerateArray())
        {
            int index = p.GetProperty("index").GetInt32();
            int typeByte = p.GetProperty("type_byte").GetInt32();
            fx.Packets.Add(new PacketEntry
            {
                Plaintext = LoadBytes(prefix + $"pkt_{index}_out.pt"),
                Ciphertext = LoadBytes(prefix + $"pkt_{index}_out.ct"),
                TypeByte = typeByte,
            });
        }

        return fx;
    }

    private static string LoadText(string resourceName)
    {
        Assembly assembly = typeof(PacketFixtureLoader).Assembly;
        using Stream? stream = assembly.GetManifestResourceStream(resourceName);
        if (stream is null)
        {
            throw new FileNotFoundException($"Fixture resource not found: {resourceName}", resourceName);
        }

        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    private static byte[] LoadBytes(string resourceName)
    {
        Assembly assembly = typeof(PacketFixtureLoader).Assembly;
        using Stream? stream = assembly.GetManifestResourceStream(resourceName);
        if (stream is null)
        {
            throw new FileNotFoundException($"Fixture resource not found: {resourceName}", resourceName);
        }

        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        return ms.ToArray();
    }
}
