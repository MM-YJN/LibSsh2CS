using System.Reflection;
using System.Security.Cryptography;

namespace LibSsh2CS.UnitTests;

/// <summary>
/// Helpers for loading embedded fixture resources and computing SSH public-key
/// fingerprints (the canonical wire-format base64 of the SSH public key blob).
/// </summary>
internal static class FixtureLoader
{
    /// <summary>
    /// Loads an embedded fixture resource as a string.
    /// </summary>
    public static string LoadText(string name)
    {
        Assembly assembly = typeof(FixtureLoader).Assembly;
        string resourceName = $"LibSsh2CS.UnitTests.Fixtures.{name}";
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
        string resourceName = $"LibSsh2CS.UnitTests.Fixtures.{name}";
        using Stream? stream = assembly.GetManifestResourceStream(resourceName);
        if (stream is null)
        {
            throw new FileNotFoundException($"Fixture not found: {resourceName}", resourceName);
        }

        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        return ms.ToArray();
    }

    /// <summary>
    /// Extracts the SSH wire-format public-key blob from a <c>.pub</c> file
    /// (format: "algorithm base64-blob comment"). Returns the decoded blob.
    /// Used to verify the public key embedded in the corresponding private key.
    /// </summary>
    public static byte[] ParsePubFileBlob(string pubFileContents)
    {
        // Format: "ssh-ed25519 AAAAC3Nz... user@host"
        // Skip the algorithm prefix; the rest before the comment is base64 of the blob.
        string[] parts = pubFileContents.TrimEnd().Split(' ', 3);
        if (parts.Length < 2)
        {
            throw new ArgumentException($"Invalid .pub file format: {pubFileContents}");
        }

        return Convert.FromBase64String(parts[1]);
    }

    /// <summary>
    /// Computes the SHA-256 base64 fingerprint of an SSH public-key blob,
    /// matching <c>ssh-keygen -lf key.pub</c> output. Used to verify parsed
    /// keys against known-good fingerprints.
    /// </summary>
    public static string ComputeSshSha256Fingerprint(byte[] publicKeyBlob)
    {
        byte[] hash = SHA256.HashData(publicKeyBlob);
        return Convert.ToBase64String(hash);
    }
}
