// Copyright (C) 2026 Yi Jin
// SPDX-License-Identifier: MIT
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace LibSsh2CS.Util;

/// <summary>
/// A pooled, consumable <see cref="IBufferWriter{Byte}"/> backed by
/// <see cref="ArrayPool{Byte}.Shared"/>. Unlike the BCL's generic
/// <see cref="ArrayBufferWriter{T}"/>, this type rents its backing array and
/// implements <see cref="IDisposable"/> to return it.
/// </summary>
/// <remarks>
/// <para>
/// <b>Lazy rental (default ctor)</b>: the parameterless constructor does not
/// rent from the pool eagerly; the writer is backed by
/// <see cref="Array.Empty{T}"/> until the first <see cref="GetMemory"/> or
/// <see cref="GetSpan"/> call. The first rent honors
/// <see cref="DefaultInitialBufferSize"/> (256) as a floor, so a large first
/// request is satisfied at <c>max(256, sizeHint)</c> bytes.
/// </para>
/// <para>
/// <b>Consume</b>: the <see cref="Consume"/> method advances a read window
/// without reclaiming the underlying storage. Written &amp; capacity
/// properties reflect only the unconsumed portion. The consumed space is
/// reclaimed lazily, except when all written data is consumed. Compaction
/// runs only when <see cref="GetMemory"/> or <see cref="GetSpan"/> is called
/// and the available <see cref="FreeCapacity"/> is insufficient, but
/// compacting would satisfy the request.
/// </para>
/// <para>
/// <b>Grow without compaction</b>: when compacting cannot satisfy a request,
/// the unconsumed content is copied directly to position 0 of a new rented
/// array, so the consumed offset drops to zero after a grow.
/// </para>
/// <para>
/// Not thread-safe (same as the BCL original). The packet layer reuses one
/// instance per direction and calls <see cref="ResetWrittenCount"/> between
/// packets, so steady-state per-packet work performs no allocation.
/// </para>
/// </remarks>
[ExcludeFromCodeCoverage]
internal sealed class PooledByteBufferWriter : IBufferWriter<byte>, IDisposable
{
    // Copy of Array.MaxLength.
    private const int ArrayMaxLength = 0x7FFFFFC7;

    private const int DefaultInitialBufferSize = 256;

    private byte[] _buffer;
    private int _index;
    private int _consumed;
    private bool _disposed;

    /// <summary>
    /// Creates a <see cref="PooledByteBufferWriter"/> with a default minimum
    /// initial capacity of 256 bytes. The backing array is rented lazily from
    /// <see cref="ArrayPool{Byte}.Shared"/> on the first call to
    /// <see cref="GetMemory"/> or <see cref="GetSpan"/>; until then the writer
    /// is backed by <see cref="Array.Empty{T}"/> and reports zero capacity.
    /// </summary>
    public PooledByteBufferWriter()
    {
        _buffer = Array.Empty<byte>();
        _index = 0;
        _consumed = 0;
    }

    /// <summary>
    /// Creates a <see cref="PooledByteBufferWriter"/> with the specified
    /// initial capacity. A capacity of zero creates an empty, lazily
    /// renting writer equivalent to the parameterless constructor.
    /// </summary>
    /// <param name="initialCapacity">The minimum initial capacity.</param>
    /// <exception cref="ArgumentException"><paramref name="initialCapacity"/>
    /// is negative.</exception>
    public PooledByteBufferWriter(int initialCapacity)
    {
        if (initialCapacity < 0)
        {
            throw new ArgumentException(null, nameof(initialCapacity));
        }

        _buffer = initialCapacity == 0 ? Array.Empty<byte>() : ArrayPool<byte>.Shared.Rent(initialCapacity);
        _index = 0;
        _consumed = 0;
    }

    /// <summary>
    /// When <see langword="true"/>, the backing array is zeroed before it is
    /// returned to the pool. Set this for writers that carry plaintext or key
    /// material; the default (<see langword="false"/>) avoids the zeroing cost
    /// for non-sensitive data.
    /// </summary>
    public bool ClearOnReturn { get; set; }

    /// <summary>
    /// Gets the unconsumed data written to the underlying buffer so far,
    /// as a <see cref="ReadOnlyMemory{T}"/>.
    /// </summary>
    public ReadOnlyMemory<byte> WrittenMemory
    {
        get
        {
            int writtenCount = _index - _consumed;
            return _buffer.AsMemory(_consumed, writtenCount);
        }
    }

    /// <summary>
    /// Gets the unconsumed data written to the underlying buffer so far,
    /// as a <see cref="ReadOnlySpan{T}"/>.
    /// </summary>
    public ReadOnlySpan<byte> WrittenSpan
    {
        get
        {
            int writtenCount = _index - _consumed;
            return _buffer.AsSpan(_consumed, writtenCount);
        }
    }

    /// <summary>
    /// Gets the amount of unconsumed data written to the underlying buffer
    /// so far.
    /// </summary>
    public int WrittenCount => _index - _consumed;

    /// <summary>
    /// Gets the total capacity of the underlying buffer, excluding the
    /// consumed portion at the start.
    /// </summary>
    public int Capacity => _buffer.Length - _consumed;

    /// <summary>
    /// Gets the amount of free space available for writing without forcing
    /// the underlying buffer to grow.
    /// </summary>
    public int FreeCapacity => _buffer.Length - _index;

    /// <inheritdoc />
    public void Advance(int count)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (count < 0)
        {
            throw new ArgumentException(null, nameof(count));
        }

        if (_index > _buffer.Length - count)
        {
            ThrowInvalidOperationException_AdvancedTooFar(_buffer.Length);
        }

        _index += count;
    }

    /// <inheritdoc />
    public Memory<byte> GetMemory(int sizeHint = 0)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        CheckAndResizeBuffer(sizeHint);
        Debug.Assert(_buffer.Length > _index);

        return _buffer.AsMemory(_index);
    }

    /// <inheritdoc />
    public Span<byte> GetSpan(int sizeHint = 0)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        CheckAndResizeBuffer(sizeHint);
        Debug.Assert(_buffer.Length > _index);

        return _buffer.AsSpan(_index);
    }

    /// <summary>
    /// Marks <paramref name="count"/> bytes at the beginning of the written
    /// data as consumed. These bytes are excluded from <see cref="WrittenMemory"/>,
    /// <see cref="WrittenSpan"/>, <see cref="WrittenCount"/>, and
    /// <see cref="Capacity"/>. The underlying storage is not reclaimed until
    /// the next call to <see cref="GetMemory"/> or <see cref="GetSpan"/>
    /// determines that compaction is required, unless all written data is consumed.
    /// </summary>
    /// <param name="count">The number of bytes to consume. Must be between
    /// 0 and <see cref="WrittenCount"/>.</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="count"/> is negative or exceeds <see cref="WrittenCount"/>.
    /// </exception>
    public void Consume(int count)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentOutOfRangeException.ThrowIfNegative(count);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(count, WrittenCount);

        if (count == WrittenCount)
        {
            _consumed = 0;
            _index = 0;
        }
        else
        {
            _consumed += count;
        }
    }

    /// <summary>Appends <paramref name="bytes"/> to the writer.</summary>
    public void Write(ReadOnlySpan<byte> bytes)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (bytes.IsEmpty)
        {
            return;
        }

        CheckAndResizeBuffer(bytes.Length);
        bytes.CopyTo(_buffer.AsSpan(_index));
        _index += bytes.Length;
    }

    /// <summary>Appends a single byte to the writer.</summary>
    public void Write(byte b)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        CheckAndResizeBuffer(1);
        _buffer[_index++] = b;
    }

    /// <summary>
    /// Clears the data written to the underlying buffer and resets the
    /// write and consume positions.
    /// </summary>
    /// <remarks>
    /// The underlying buffer is not returned to the pool. To return the
    /// buffer, call <see cref="Dispose"/>.
    /// </remarks>
    public void Clear()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        Debug.Assert(_buffer.Length >= _index);

        _buffer.AsSpan(0, _index).Clear();
        _consumed = 0;
        _index = 0;
    }

    /// <summary>
    /// Resets the write and consume positions without zeroing the
    /// underlying buffer.
    /// </summary>
    /// <remarks>
    /// This is faster than <see cref="Clear"/> since it only adjusts the
    /// position markers. Callers must not rely on the buffer content being
    /// zeroed after this call.
    /// </remarks>
    public void ResetWrittenCount()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        _consumed = 0;
        _index = 0;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (!_disposed)
        {
            _disposed = true;

            byte[] toReturn = _buffer;
            _buffer = Array.Empty<byte>();
            _index = 0;
            _consumed = 0;

            if (toReturn.Length > 0)
            {
                ArrayPool<byte>.Shared.Return(toReturn, clearArray: ClearOnReturn);
            }
        }
    }

    private void CheckAndResizeBuffer(int sizeHint)
    {
        if (sizeHint < 0)
        {
            throw new ArgumentException("Size hint must not be negative.", nameof(sizeHint));
        }

        if (sizeHint == 0)
        {
            sizeHint = 1;
        }

        if (sizeHint > FreeCapacity)
        {
            int writtenCount = WrittenCount;

            if (sizeHint <= _buffer.Length - writtenCount)
            {
                if (_consumed > 0 && writtenCount > 0)
                {
                    Buffer.BlockCopy(_buffer, _consumed, _buffer, 0, writtenCount);
                }

                _index = writtenCount;
                _consumed = 0;
            }
            else
            {
                GrowBuffer(sizeHint, writtenCount);
            }
        }

        Debug.Assert(FreeCapacity > 0 && FreeCapacity >= sizeHint);
    }

    private void GrowBuffer(int sizeHint, int writtenCount)
    {
        Debug.Assert(sizeHint > _buffer.Length - writtenCount);

        uint requiredSize = (uint)writtenCount + (uint)sizeHint;
        if (requiredSize > ArrayMaxLength)
        {
            ThrowOutOfMemoryException(requiredSize);
        }

        uint doubledSize = _buffer.Length == 0 ? DefaultInitialBufferSize : (uint)_buffer.Length * 2;
        uint newSize = Math.Min(Math.Max(requiredSize, doubledSize), ArrayMaxLength);
        byte[] newBuffer = ArrayPool<byte>.Shared.Rent((int)newSize);

        if (writtenCount > 0)
        {
            Buffer.BlockCopy(_buffer, _consumed, newBuffer, 0, writtenCount);
        }

        if (_buffer.Length > 0)
        {
            ArrayPool<byte>.Shared.Return(_buffer, clearArray: ClearOnReturn);
        }

        _buffer = newBuffer;
        _index = writtenCount;
        _consumed = 0;
    }

    private static void ThrowInvalidOperationException_AdvancedTooFar(int capacity)
    {
        throw new InvalidOperationException($"BufferWriterAdvancedTooFar: {capacity}");
    }

    private static void ThrowOutOfMemoryException(uint capacity)
    {
        throw new InvalidOperationException($"BufferMaximumSizeExceeded: {capacity}");
    }
}
