using System.Buffers;
using System.Diagnostics;

namespace LibSsh2CS.Util;

[System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
internal sealed class MemoryPoolBufferWriter : IBufferWriter<byte>, IDisposable
{
    private sealed class BufferSegment : ReadOnlySequenceSegment<byte>
    {
        private IMemoryOwner<byte>? _memoryOwner;
        private Memory<byte> _memory;
        private BufferSegment? _next;
        private int _consumed;

        public int Length => _consumed;

        public int AvailableLength => _memory.Length - _consumed;

        public Memory<byte> AvailableMemory => _memory[_consumed..];

        public Span<byte> AvailableSpan => _memory.Span[_consumed..];

        public BufferSegment? NextSegment => _next;

        public BufferSegment(long runningIndex, IMemoryOwner<byte> memoryOwner)
        {
            _memoryOwner = memoryOwner;
            _memory = memoryOwner.Memory;
            _consumed = 0;

            Memory = default;
            RunningIndex = runningIndex;
        }

        public void Advance(int count)
        {
            Debug.Assert(count <= AvailableLength);

            _consumed += count;
            Memory = _memory[.._consumed];
        }

        public void SetNext(BufferSegment segment)
        {
            _next = segment;

            Next = segment;
        }

        public void CopyTo(Span<byte> destination)
            => _memory.Span[.._consumed].CopyTo(destination);

        public BufferSegment? ReturnMemory()
        {
            BufferSegment? next = _next;

            _memoryOwner?.Dispose();
            _memoryOwner = null;
            _memory = default;
            _next = null;

            Memory = default;
            Next = default;

            return next;
        }
    }

    private readonly int _defaultSegmentSize;
    private readonly MemoryPool<byte> _memoryPool;
    private BufferSegment? _head;
    private BufferSegment? _current;
    private int _length;

    public int Length => _length;

#pragma warning disable IDE0290 // Use primary constructor
    public MemoryPoolBufferWriter(int defaultSegmentSize = 16384, MemoryPool<byte>? memoryPool = null)
#pragma warning restore IDE0290 // Use primary constructor
    {
        _defaultSegmentSize = defaultSegmentSize;
        _memoryPool = memoryPool ?? MemoryPool<byte>.Shared;
    }

    private BufferSegment GetBufferSegment(int sizeHint)
    {
        BufferSegment? current = _current;
        if (current is null)
        {
            _head = _current = current = new BufferSegment(0, _memoryPool.Rent(Math.Max(sizeHint, _defaultSegmentSize)));
        }
        if (sizeHint < current.AvailableLength)
        {
            return current;
        }

        Debug.Assert(_current != null);
        current = new BufferSegment(_length, _memoryPool.Rent(Math.Max(sizeHint, _defaultSegmentSize)));
        _current!.SetNext(current);
        _current = current;

        return current;
    }

    public Memory<byte> GetMemory(int sizeHint = 0)
        => GetBufferSegment(sizeHint).AvailableMemory;

    public Span<byte> GetSpan(int sizeHint = 0)
        => GetBufferSegment(sizeHint).AvailableSpan;

    public void Advance(int count)
    {
        BufferSegment? current = _current;
        if (current is null)
        {
            throw new InvalidOperationException();
        }
        ArgumentOutOfRangeException.ThrowIfGreaterThan(count, current.AvailableLength);

        current.Advance(count);
        _length += count;
    }

    public byte[] ToArray()
    {
        int totalLength = 0;
        BufferSegment? segment = _head;
        while (segment != null)
        {
            totalLength += segment.Length;
            segment = segment.NextSegment;
        }

        byte[] destination = new byte[totalLength];
        int offset = 0;
        segment = _head;
        while (segment != null)
        {
            segment.CopyTo(destination.AsSpan(offset));
            offset += segment.Length;
            segment = segment.NextSegment;
        }

        return destination;
    }

    public void CopyTo(Span<byte> destination)
    {
        BufferSegment? segment = _head;
        while (segment != null)
        {
            segment.CopyTo(destination);
            destination = destination[segment.Length..];
            segment = segment.NextSegment;
        }
    }

    public ReadOnlySequence<byte> GetReadOnlySequence()
    {
        if (_head is null || _current is null)
        {
            return ReadOnlySequence<byte>.Empty;
        }

        return new ReadOnlySequence<byte>(_head, 0, _current, _current.Length);
    }

    public void Dispose()
    {
        BufferSegment? segment = _head;
        while (segment != null)
        {
            segment = segment.ReturnMemory();
        }
        _head = _current = null;
        _length = 0;
    }
}
