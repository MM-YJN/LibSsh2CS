namespace LibSsh2CS.IntegrationTests.TestKit.Logger;

/// <summary>
/// A thread-safe wrapper around <see cref="ITestOutputHelper"/> to ensure that output from multiple threads does not interleave and remains coherent.
/// </summary>
public sealed class SynchronizedTestOutputHelper : ITestOutputHelper
{
    private readonly ITestOutputHelper _inner;
    private readonly Lock _lock = new();

    /// <summary>
    /// Initializes a new instance of the <see cref="SynchronizedTestOutputHelper"/> class that wraps the specified <see cref="ITestOutputHelper"/> instance.
    /// </summary>
    /// <param name="inner">The <see cref="ITestOutputHelper"/> instance to wrap. Must not be null.</param>
    public SynchronizedTestOutputHelper(ITestOutputHelper inner)
    {
        ArgumentNullException.ThrowIfNull(inner);
        _inner = inner;
    }

    /// <inheritdoc />
    public string Output
    {
        get
        {
            lock (_lock)
            {
                return _inner.Output;
            }
        }
    }

    /// <inheritdoc />
    public void Write(string message)
    {
        lock (_lock)
        {
            _inner.Write(message);
        }
    }

    /// <inheritdoc />
    public void Write(string format, params object[] args)
    {
        lock (_lock)
        {
            _inner.Write(format, args);
        }
    }

    /// <inheritdoc />
    public void WriteLine(string message)
    {
        lock (_lock)
        {
            _inner.WriteLine(message);
        }
    }

    /// <inheritdoc />
    public void WriteLine(string format, params object[] args)
    {
        lock (_lock)
        {
            _inner.WriteLine(format, args);
        }
    }
}
