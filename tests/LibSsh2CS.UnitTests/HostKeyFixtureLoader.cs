using System.Reflection;

namespace LibSsh2CS.UnitTests;

/// <summary>
/// Loads one captured host-key oracle from <c>Fixtures/hostkey/&lt;type&gt;/</c>
/// (produced by <c>Capture/capture-packets.py --sections hostkey</c>). Carries the
/// three byte-exact inputs to <see cref="LibSsh2CS.Transport.HostKeyVerifier.Verify"/>:
/// the server host-key blob <c>K_S</c>, the exchange hash <c>H</c> (signed
/// message), and the raw signature blob.
/// </summary>
internal sealed class HostKeyFixture
{
    public SshHostKeyType Type { get; set; }
    public byte[] HostKey { get; set; } = Array.Empty<byte>();      // K_S
    public byte[] ExchangeHash { get; set; } = Array.Empty<byte>(); // H
    public byte[] Sig { get; set; } = Array.Empty<byte>();          // raw sig blob
}

internal static class HostKeyFixtureLoader
{
    /// <summary>Loads the host-key fixture for a type dir name (e.g. "ssh-ed25519").</summary>
    public static HostKeyFixture Load(string typeDir)
    {
        // MSBuild rewrites hyphens in fixture FOLDER names to underscores.
        string resType = typeDir.Replace('-', '_');
        string prefix = $"LibSsh2CS.UnitTests.Fixtures.hostkey.{resType}.";

        return new HostKeyFixture
        {
            Type = TypeFor(typeDir),
            HostKey = LoadBytes(prefix + "host_key.bin"),
            ExchangeHash = LoadBytes(prefix + "exchange_hash.bin"),
            Sig = LoadBytes(prefix + "sig.bin"),
        };
    }

    /// <summary>Loads all 7 in-scope host-key fixtures.</summary>
    public static IEnumerable<HostKeyFixture> LoadAll()
        => new[]
        {
            "ssh-ed25519",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
            "rsa-sha2-256",
            "rsa-sha2-512",
            "ssh-rsa",
        }.Select(Load);

    private static SshHostKeyType TypeFor(string typeDir) => typeDir switch
    {
        "ssh-ed25519" => SshHostKeyType.Ed25519,
        "ecdsa-sha2-nistp256" => SshHostKeyType.Ecdsa256,
        "ecdsa-sha2-nistp384" => SshHostKeyType.Ecdsa384,
        "ecdsa-sha2-nistp521" => SshHostKeyType.Ecdsa521,
        "rsa-sha2-256" => SshHostKeyType.RsaSha256,
        "rsa-sha2-512" => SshHostKeyType.RsaSha512,
        "ssh-rsa" => SshHostKeyType.SshRsa,
        _ => throw new ArgumentOutOfRangeException(nameof(typeDir), $"unknown hostkey fixture dir: {typeDir}"),
    };

    private static byte[] LoadBytes(string resourceName)
    {
        Assembly assembly = typeof(HostKeyFixtureLoader).Assembly;
        using Stream? stream = assembly.GetManifestResourceStream(resourceName)
            ?? throw new FileNotFoundException($"hostkey fixture resource not found: {resourceName}", resourceName);
        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        return ms.ToArray();
    }
}
