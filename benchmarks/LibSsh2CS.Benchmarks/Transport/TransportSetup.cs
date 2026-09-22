using System.IO.Pipelines;

using LibSsh2CS.Transport;

namespace LibSsh2CS.Benchmarks.Transport;

/// <summary>
/// Shared setup for the transport benchmarks: builds cipher/MAC/compression
/// triples with deterministic key material so a decrypting
/// <see cref="PacketReader"/> can be paired with an encrypting
/// <see cref="PacketWriter"/> (and vice versa) without a live key exchange.
/// </summary>
internal static class TransportSetup
{
    /// <summary>
    /// Creates a cipher with deterministic key/IV for the given wire name and
    /// its MAC. AEAD ciphers get the no-op MAC (their tag is integrated under
    /// the cipher); other ciphers use <paramref name="macName"/>.
    /// </summary>
    public static (ICipher Cipher, IMac Mac) CreateCipherAndMac(
        string cipherName, string? macName, bool encrypt)
    {
        ICipher cipher = CipherMethods.Create(cipherName)
            ?? throw new ArgumentException($"Unknown cipher '{cipherName}'", nameof(cipherName));
        cipher.Init(
            DeterministicBytes(cipher.KeyLen, 0x11),
            DeterministicBytes(cipher.IvLen, 0x22),
            encrypt);

        IMac mac;
        if (CipherMethods.IsAead(cipher))
        {
            mac = MacMethods.Noop;
        }
        else
        {
            string name = macName ?? "hmac-sha2-256";
            mac = MacMethods.Create(name)
                ?? throw new ArgumentException($"Unknown MAC '{name}'", nameof(macName));
            mac.Init(DeterministicBytes(mac.MacLen, 0x33));
        }

        return (cipher, mac);
    }

    /// <summary>Creates a compression method in the given direction.</summary>
    public static ICompression CreateCompression(string name, bool compress)
    {
        ICompression compression = CompressionMethods.Create(name)
            ?? throw new ArgumentException($"Unknown compression '{name}'", nameof(name));
        compression.Init(compress);
        return compression;
    }

    /// <summary>
    /// Creates a pipe with a large pause threshold so the benchmarked side of
    /// the pipe observes a continuously-buffered stream instead of backpressure
    /// stalls that would dominate the timing.
    /// </summary>
    public static Pipe CreatePipe(int megabytes = 64)
        => new(new PipeOptions(
            pauseWriterThreshold: megabytes * 1024L * 1024L,
            resumeWriterThreshold: megabytes * 1024L * 1024L / 2));

    private static byte[] DeterministicBytes(int length, byte seed)
    {
        byte[] bytes = new byte[length];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = (byte)(seed + (i * 31));
        }

        return bytes;
    }
}
