using System.IO.Pipelines;

namespace LibSsh2CS.Util;

/// <summary>
/// A minimal <see cref="IDuplexPipe"/> over a bidirectional <see cref="Stream"/>:
/// <see cref="Input"/> is a <see cref="PipeReader"/> wrapping the stream,
/// <see cref="Output"/> is a <see cref="PipeWriter"/> wrapping the same stream. Used to feed
/// the SSH transport (<see cref="Transport.PacketReader"/> /
/// <see cref="Transport.PacketWriter"/>) from a TCP <see cref="System.Net.Sockets.NetworkStream"/>
/// or any other bidirectional stream.
/// </summary>
/// <remarks>
/// Moved into the library from its original location
/// as a private nested class in the test project's <c>DockerHandshakeTests</c>.
/// The <c>SshSession.HandshakeAsync(Stream, verifyHostKeyAsync, CancellationToken)</c> convenience
/// overload wraps a caller-supplied stream via this type. The session does NOT
/// own or dispose the stream or the pipe — the caller does.
/// </remarks>
internal sealed class StreamDuplexPipe : IDuplexPipe
{
    /// <summary>
    /// Constructs a duplex pipe over <paramref name="stream"/>. The stream must
    /// be readable and writable (e.g. <see cref="System.Net.Sockets.NetworkStream"/>
    /// with default construction, or a paired test pipe).
    /// </summary>
    public StreamDuplexPipe(Stream stream)
    {
        Input = PipeReader.Create(stream);
        Output = PipeWriter.Create(stream);
    }

    /// <inheritdoc/>
    public PipeReader Input { get; }

    /// <inheritdoc/>
    public PipeWriter Output { get; }
}
