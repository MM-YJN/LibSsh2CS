namespace LibSsh2CS.Util;

/// <summary>
/// Base64 decoding with libssh2's exact leniency semantics
/// (<c>misc.c:396-424</c>): every non-alphabet byte — whitespace,
/// <c>'='</c>, punctuation, junk — is SKIPPED; the only failure is a single
/// leftover sextet (<c>i % 4 == 1</c>), which throws
/// <see cref="SshErrorCode.Inval"/> "Invalid base64". The BCL decoders
/// require canonical padding and reject stray characters, so files the C
/// accepts (unpadded <c>|1|salt|hash|</c> known_hosts fields, PEM bodies
/// with stray characters) were rejected or never matched by the port.
/// </summary>
internal static class LenientBase64
{
    /// <summary>
    /// Decodes with the C's exact semantics into a fresh array. The maximum
    /// output length is <paramref name="src"/>.Length (the 4:3 ratio bounds
    /// it strictly below); the caller should zero the result after use (it
    /// may hold key material).
    /// </summary>
    public static byte[] Decode(ReadOnlySpan<byte> src)
    {
        byte[] output = new byte[Math.Max(src.Length, 1)];
        int length = Decode(src, output);
        return output.AsSpan(0, length).ToArray();
    }

    /// <summary>
    /// Decodes with the C's exact semantics into <paramref name="destination"/>
    /// and returns the number of bytes written. The destination must be at
    /// least <paramref name="src"/>.Length bytes (the decoded length is always
    /// ≤ ceil(valid_sextets * 3 / 4) &lt; src.Length for non-empty input).
    /// </summary>
    /// <exception cref="SshException">Thrown with <see cref="SshErrorCode.Inval"/>
    /// when a single leftover sextet remains (the C's only failure,
    /// <c>misc.c:418-424</c>).</exception>
    public static int Decode(ReadOnlySpan<byte> src, Span<byte> destination)
    {
        int i = 0;   // number of valid sextets consumed
        int len = 0; // bytes written
        foreach (byte b in src)
        {
            int v = ValueOf(b);
            if (v < 0)
            {
                continue;   // skip: whitespace, '=', junk (misc.c:396-399)
            }

            switch (i % 4)
            {
                case 0:
                    destination[len] = (byte)(v << 2);
                    break;
                case 1:
                    destination[len++] |= (byte)(v >> 4);
                    destination[len] = (byte)(v << 4);
                    break;
                case 2:
                    destination[len++] |= (byte)(v >> 2);
                    destination[len] = (byte)(v << 6);
                    break;
                case 3:
                    destination[len++] |= (byte)v;
                    break;
            }

            i++;
        }

        if (i % 4 == 1)
        {
            // A byte which belongs exclusively to a partial octet
            // (misc.c:418-424).
            throw new SshException(SshErrorCode.Inval, "Invalid base64");
        }

        return len;
    }

    /// <summary>Char overload (ASCII text inputs — known_hosts fields).</summary>
    public static byte[] Decode(ReadOnlySpan<char> src)
    {
        byte[] output = new byte[Math.Max(src.Length, 1)];
        int length = Decode(src, output);
        return output.AsSpan(0, length).ToArray();
    }

    /// <summary>
    /// Char overload writing into <paramref name="destination"/>; returns the
    /// number of bytes written (see the byte-span overload for the contract).
    /// </summary>
    public static int Decode(ReadOnlySpan<char> src, Span<byte> destination)
    {
        int i = 0;
        int len = 0;
        foreach (char ch in src)
        {
            int v = ValueOf((byte)ch);
            if (v < 0)
            {
                continue;
            }

            switch (i % 4)
            {
                case 0:
                    destination[len] = (byte)(v << 2);
                    break;
                case 1:
                    destination[len++] |= (byte)(v >> 4);
                    destination[len] = (byte)(v << 4);
                    break;
                case 2:
                    destination[len++] |= (byte)(v >> 2);
                    destination[len] = (byte)(v << 6);
                    break;
                case 3:
                    destination[len++] |= (byte)v;
                    break;
            }

            i++;
        }

        if (i % 4 == 1)
        {
            throw new SshException(SshErrorCode.Inval, "Invalid base64");
        }

        return len;
    }

    /// <summary>
    /// The base64 alphabet value of <paramref name="c"/>, or -1 for every
    /// non-alphabet byte (mirrors <c>base64_reverse_table</c>,
    /// <c>misc.c:337-354</c> — all other bytes map to -1 and are skipped).
    /// </summary>
    private static int ValueOf(byte c) => c switch
    {
        >= (byte)'A' and <= (byte)'Z' => c - (byte)'A',
        >= (byte)'a' and <= (byte)'z' => c - (byte)'a' + 26,
        >= (byte)'0' and <= (byte)'9' => c - (byte)'0' + 52,
        (byte)'+' => 62,
        (byte)'/' => 63,
        _ => -1,
    };
}
