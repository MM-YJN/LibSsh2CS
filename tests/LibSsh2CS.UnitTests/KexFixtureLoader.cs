using System.Reflection;
using System.Text.Json;

namespace LibSsh2CS.UnitTests;

/// <summary>
/// Loads one captured KEX-method oracle from <c>Fixtures/kex/&lt;method&gt;/</c>
/// (produced by <c>Capture/capture-packets.py</c>). Carries the exchange-hash
/// inputs, the H oracle, and the A-F derived-key oracle for the KATs.
/// </summary>
internal sealed class KexFixture
{
    public string Kex { get; set; } = "";
    public string Hash { get; set; } = "";
    public string EFieldEncoding { get; set; } = "";   // "mpint" (DH) or "string" (ECDH/curve25519)
    public byte[] ClientBanner { get; set; } = Array.Empty<byte>();   // V_C
    public byte[] ServerBanner { get; set; } = Array.Empty<byte>();   // V_S
    public byte[] ClientKexInit { get; set; } = Array.Empty<byte>();  // I_C
    public byte[] ServerKexInit { get; set; } = Array.Empty<byte>();  // I_S
    public byte[] HostKey { get; set; } = Array.Empty<byte>();        // K_S
    public byte[] ClientEphemeral { get; set; } = Array.Empty<byte>();  // e / Q_C
    public byte[] ServerEphemeral { get; set; } = Array.Empty<byte>();  // f / Q_S
    public byte[] SharedSecret { get; set; } = Array.Empty<byte>();     // K (raw BE)
    public byte[] ExchangeHash { get; set; } = Array.Empty<byte>();     // H oracle
    public Dictionary<string, string> DerivedKeys { get; set; } = new();  // A-F hex
}

internal static class KexFixtureLoader
{
    /// <summary>Loads the KEX fixture for a method dir name (e.g. "curve25519-sha256").</summary>
    public static KexFixture Load(string methodDir)
    {
        // MSBuild rewrites hyphens in fixture FOLDER names to underscores.
        string resMethod = methodDir.Replace('-', '_');
        string prefix = $"LibSsh2CS.UnitTests.Fixtures.kex.{resMethod}.";

        var fx = new KexFixture();
        string metaJson = LoadText(prefix + "meta.json");
        using var doc = JsonDocument.Parse(metaJson);
        JsonElement root = doc.RootElement;
        fx.Kex = root.GetProperty("kex").GetString() ?? "";
        fx.Hash = root.GetProperty("hash").GetString() ?? "";
        fx.EFieldEncoding = root.GetProperty("e_field_encoding").GetString() ?? "";

        foreach (JsonProperty p in root.GetProperty("derived_keys").EnumerateObject())
        {
            fx.DerivedKeys[p.Name] = p.Value.GetString() ?? "";
        }

        // version_strings.txt — "VC=...\nVS=...\n"
        string vs = LoadText(prefix + "version_strings.txt");
        foreach (string line in vs.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            string s = line.Trim();
            if (s.StartsWith("VC="))
            {
                fx.ClientBanner = System.Text.Encoding.ASCII.GetBytes(s[3..]);
            }
            else if (s.StartsWith("VS="))
            {
                fx.ServerBanner = System.Text.Encoding.ASCII.GetBytes(s[3..]);
            }
        }

        fx.ClientKexInit = LoadBytes(prefix + "client_kexinit.bin");
        fx.ServerKexInit = LoadBytes(prefix + "server_kexinit.bin");
        fx.HostKey = LoadBytes(prefix + "host_key.bin");
        fx.ClientEphemeral = LoadBytes(prefix + "client_ephemeral.bin");
        fx.ServerEphemeral = LoadBytes(prefix + "server_ephemeral.bin");
        fx.SharedSecret = LoadBytes(prefix + "shared_secret.bin");
        fx.ExchangeHash = LoadBytes(prefix + "exchange_hash.bin");
        return fx;
    }

    private static string LoadText(string resourceName)
    {
        Assembly assembly = typeof(KexFixtureLoader).Assembly;
        using Stream? stream = assembly.GetManifestResourceStream(resourceName)
            ?? throw new FileNotFoundException($"KEX fixture resource not found: {resourceName}", resourceName);
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    private static byte[] LoadBytes(string resourceName)
    {
        Assembly assembly = typeof(KexFixtureLoader).Assembly;
        using Stream? stream = assembly.GetManifestResourceStream(resourceName)
            ?? throw new FileNotFoundException($"KEX fixture resource not found: {resourceName}", resourceName);
        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        return ms.ToArray();
    }
}
