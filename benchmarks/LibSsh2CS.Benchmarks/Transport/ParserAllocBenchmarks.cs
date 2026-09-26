using System.Buffers;
using System.Buffers.Binary;
using System.Text;

using BenchmarkDotNet.Attributes;

using LibSsh2CS.Transport;
using LibSsh2CS.Util;

namespace LibSsh2CS.Benchmarks.Transport;

/// <summary>Measures packet parsing with inputs prepared outside measurement.</summary>
[MemoryDiagnoser]
public class ParserAllocBenchmarks
{
    private byte[] _kex = null!;
    private byte[] _ext = null!;

    [GlobalSetup]
    public void Setup()
    {
        _kex = KeyExchange.BuildKexInit(new MethodPreferences());
        using var stream = new MemoryStream();
        stream.WriteByte((byte)PacketType.ExtInfo);
        stream.Write(new byte[] { 0, 0, 0, 2 });
        foreach (string value in new[] { "server-sig-algs", "ssh-ed25519,rsa-sha2-256,rsa-sha2-512", "ping@openssh.com", "0" })
        {
            byte[] bytes = Encoding.UTF8.GetBytes(value);
            byte[] length = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(length, (uint)bytes.Length);
            stream.Write(length);
            stream.Write(bytes);
        }
        _ext = stream.ToArray();
    }

    [Benchmark]
    public int ParseKexInit() => KeyExchange.ParseKexInit(_kex).KexAlgorithms.Length;

    [Benchmark]
    public int ParseExtInfo() => ExtInfo.Parse(_ext).Extensions.Length;
}

/// <summary>Measures contiguous string decoding and the segmented fallback.</summary>
[MemoryDiagnoser]
public class StringDecodeAllocBenchmarks
{
    [Params("empty", "ascii", "unicode", "malformed")]
    public string TextKind { get; set; } = "ascii";

    [Params(false, true)]
    public bool Segmented { get; set; }

    private ReadOnlySequence<byte> _input;

    [GlobalSetup]
    public void Setup()
    {
        byte[] body = TextKind switch
        {
            "empty" => [],
            "ascii" => Encoding.UTF8.GetBytes("ssh-ed25519,rsa-sha2-256,rsa-sha2-512"),
            "unicode" => Encoding.UTF8.GetBytes("鍵交換🔑"),
            _ => [0xE9, 0x8D, 0xB5, 0xF0, 0x9F, 0xFF, 0x80],
        };
        byte[] wire = new byte[4 + body.Length];
        BinaryPrimitives.WriteUInt32BigEndian(wire, (uint)body.Length);
        body.CopyTo(wire, 4);
        if (Segmented)
        {
            int split = body.Length == 0 ? 2 : 5;
            var first = new Segment(wire.AsMemory(0, split));
            Segment last = first.Append(wire.AsMemory(split));
            _input = new ReadOnlySequence<byte>(first, 0, last, last.Memory.Length);
        }
        else
        {
            _input = new ReadOnlySequence<byte>(wire);
        }
        if (Decode() != Encoding.UTF8.GetString(body))
        {
            throw new InvalidOperationException("Unexpected decoded string.");
        }
    }

    [Benchmark]
    public string Decode()
    {
        var reader = new PacketWireReader(_input);
        return reader.ReadString();
    }

    private sealed class Segment : ReadOnlySequenceSegment<byte>
    {
        public Segment(ReadOnlyMemory<byte> memory) => Memory = memory;

        public Segment Append(ReadOnlyMemory<byte> memory)
        {
            var next = new Segment(memory) { RunningIndex = RunningIndex + Memory.Length };
            Next = next;
            return next;
        }
    }
}
