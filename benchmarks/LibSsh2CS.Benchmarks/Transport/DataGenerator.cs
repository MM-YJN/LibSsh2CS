namespace LibSsh2CS.Benchmarks.Transport;

/// <summary>
/// Selects whether <see cref="DataGenerator"/> produces payloads that compress
/// well. The packet benchmarks use <see cref="Compressible"/> so the zlib cases
/// exercise the real dictionary compression path; the compression benchmarks
/// cover both shapes because incompressible input is the zlib codec's worst case.
/// </summary>
public enum DataShape
{
    /// <summary>Highly repetitive payload (a repeated ASCII sentence).</summary>
    Compressible,

    /// <summary>Fixed-seed pseudo-random payload (incompressible).</summary>
    Incompressible,
}

/// <summary>
/// Deterministic payload generators for the transport benchmarks — fixed
/// content keeps allocation measurements comparable across runs and avoids
/// measuring RNG work.
/// </summary>
public static class DataGenerator
{
    private static readonly byte[] s_sentence =
        "The quick brown fox jumps over the lazy dog. "u8.ToArray();

    /// <summary>Creates a payload of <paramref name="size"/> bytes with the given compressibility.</summary>
    public static byte[] Create(DataShape shape, int size)
        => shape == DataShape.Compressible ? Compressible(size) : Incompressible(size);

    private static byte[] Compressible(int size)
    {
        byte[] data = new byte[size];
        for (int i = 0; i < data.Length; i++)
        {
            data[i] = s_sentence[i % s_sentence.Length];
        }

        return data;
    }

    private static byte[] Incompressible(int size)
    {
        byte[] data = new byte[size];
        // Fixed-seed PRNG: deterministic, and setup-only (never measured).
        var random = new Random(0x5EED);
        random.NextBytes(data);
        return data;
    }
}
