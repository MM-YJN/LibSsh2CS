namespace LibSsh2CS;

/// <summary>
/// Callback delegate for host key verification. Invoked during the handshake after the server's host key is received and its signature is verified. The callback should return <c>true</c> to accept the host key, or <c>false</c> to reject it.
/// </summary>
/// <param name="hostKey">The server's host key.</param>
/// <param name="signature">The signature of the host key.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>A task that represents the asynchronous operation. The task result is <c>true</c> to accept the host key, or <c>false</c> to reject it.</returns>
public delegate Task<bool> HostKeyVerificationCallback(ReadOnlyMemory<byte> hostKey, ReadOnlyMemory<byte> signature, CancellationToken cancellationToken);
