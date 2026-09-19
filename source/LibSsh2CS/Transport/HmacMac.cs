using System.Buffers.Binary;
using System.Security.Cryptography;

namespace LibSsh2CS.Transport;

/// <summary>
/// HMAC-SHA1 / SHA256 / SHA512. Built on the BCL <see cref="IncrementalHash"/> HMAC,
/// which keeps the keyed state across packets and resets per message via
/// <c>TryGetHashAndReset</c> — one context per direction, like libssh2.
/// </summary>
internal sealed class HmacMac : IMac
{
    private readonly string _name;
    private readonly HashAlgorithmName _hashName;
    private readonly int _macLen;
    private readonly bool _isEtm;
    private byte[]? _key;
    private IncrementalHash? _hmac;

    public HmacMac(string name, HashAlgorithmName hashName, int macLen, bool isEtm)
    {
        _name = name;
        _hashName = hashName;
        _macLen = macLen;
        _isEtm = isEtm;
    }

    public string Name => _name;
    public int MacLen => _macLen;
    public bool IsEtm => _isEtm;

    public void Init(ReadOnlySpan<byte> key)
    {
        _hmac?.Dispose();
        _key = key.ToArray();
        _hmac = IncrementalHash.CreateHMAC(_hashName, _key);
    }

    public void Compute(uint seqno, ReadOnlySpan<byte> data, Span<byte> mac)
    {
        if (_hmac is null)
        {
            throw new InvalidOperationException($"{_name}: Init not called");
        }

        if (mac.Length < _macLen)
        {
            throw new ArgumentException("MAC output buffer too small", nameof(mac));
        }

        Span<byte> seqbuf = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(seqbuf, seqno);
        _hmac.AppendData(seqbuf);
        _hmac.AppendData(data);

        if (!_hmac.TryGetHashAndReset(mac.Slice(0, _macLen), out int written) || written != _macLen)
        {
            throw new SshException(SshErrorCode.Inval, $"{_name}: HMAC produced {written} bytes, expected {_macLen}");
        }
    }

    public bool Verify(uint seqno, ReadOnlySpan<byte> data, ReadOnlySpan<byte> mac)
    {
        if (mac.Length != _macLen)
        {
            return false;
        }

        Span<byte> expected = stackalloc byte[_macLen];
        Compute(seqno, data, expected);
        return CryptographicOperations.FixedTimeEquals(expected, mac);
    }

    public void Dispose()
    {
        _hmac?.Dispose();
        _hmac = null;

        if (_key is not null)
        {
            CryptographicOperations.ZeroMemory(_key);
            _key = null;
        }
    }
}
