using System.Reflection;

namespace LibSsh2CS.IntegrationTests;

/// <summary>
/// Slim copy of <c>FixtureLoader</c> for integration tests: loads embedded
/// fixture resources (SSH private/public key files used by the Docker tests).
/// The full <c>FixtureLoader</c> (with <c>ParsePubFileBlob</c> and
/// <c>ComputeSshSha256Fingerprint</c> helpers) stays in
/// <c>LibSsh2CS.UnitTests</c>.
/// </summary>
internal static class FixtureLoader
{
    /// <summary>
    /// Loads an embedded fixture resource as a string.
    /// </summary>
    public static string LoadText(string name)
    {
        Assembly assembly = typeof(FixtureLoader).Assembly;
        string resourceName = $"LibSsh2CS.IntegrationTests.Fixtures.{name}";
        using Stream? stream = assembly.GetManifestResourceStream(resourceName);
        if (stream is null)
        {
            throw new FileNotFoundException($"Fixture not found: {resourceName}", resourceName);
        }

        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    /// <summary>
    /// Loads an embedded fixture resource as raw bytes.
    /// </summary>
    public static byte[] LoadBytes(string name)
    {
        Assembly assembly = typeof(FixtureLoader).Assembly;
        string resourceName = $"LibSsh2CS.IntegrationTests.Fixtures.{name}";
        using Stream? stream = assembly.GetManifestResourceStream(resourceName);
        if (stream is null)
        {
            throw new FileNotFoundException($"Fixture not found: {resourceName}", resourceName);
        }

        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        return ms.ToArray();
    }
}
