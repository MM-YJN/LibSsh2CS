using System.Buffers;
using System.Security.Cryptography;

namespace LibSsh2CS.Transport;

/// <summary>
/// A decrypted, MAC-verified, decompressed inbound SSH packet — the output of
/// <see cref="PacketReader.ReadPacketAsync"/>. The <see cref="Payload"/> begins
/// with the <c>SSH_MSG_*</c> type byte; <see cref="Seqno"/> is the inbound
/// sequence number the packet was sent under (recorded before any strict-KEX
/// NEWKEYS reset, so the caller can observe the reset).
/// </summary>
/// <remarks>
/// Minimal carrier with no queueing logic or type filtering.
/// <see cref="PacketQueue"/> handles inline DISCONNECT / IGNORE / DEBUG / EXT_INFO packets.
/// </remarks>
internal readonly struct RawPacket : IDisposable
{
    /// <summary>The <c>SSH_MSG_*</c> type byte (<see cref="PacketType"/>).</summary>
    public int Type { get; }

    /// <summary>
    /// The full decrypted payload, beginning with the type byte. Owned by the caller until disposed or transferred to another owner.
    /// Only the payload length is exposed, never pooled capacity.
    /// </summary>
    public ReadOnlyMemory<byte> Payload { get; }

    internal PayloadLease? Lease { get; }

    public bool HasPacket { get; }

    public void Dispose() => Lease?.Dispose();

    /// <summary>
    /// The inbound sequence number this packet carried (pre-NEWKEYS-reset if
    /// the packet was a NEWKEYS under strict-KEX).
    /// </summary>
    public uint Seqno { get; }

    public RawPacket(int type, ReadOnlyMemory<byte> payload, uint seqno, PayloadLease? lease = null)
    {
        HasPacket = true;
        Lease = lease;
        Type = type;
        Payload = payload;
        Seqno = seqno;
    }
}

/// <summary>Shared return guard for copies of a packet; not reference counted.</summary>
internal sealed class PayloadLease(ArrayPool<byte> pool, byte[] buffer, int length) : IDisposable
{
    private byte[]? _buffer = buffer;

    public void Dispose()
    {
        byte[]? array = Interlocked.Exchange(ref _buffer, null);
        if (array is not null)
        {
            CryptographicOperations.ZeroMemory(array.AsSpan(0, length));
            pool.Return(array);
        }
    }
}
