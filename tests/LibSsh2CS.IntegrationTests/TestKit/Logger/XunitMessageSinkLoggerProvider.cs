using Microsoft.Extensions.Logging;

using Xunit.Sdk;

namespace LibSsh2CS.IntegrationTests.TestKit.Logger;

/// <summary>
/// Provides an <see cref="ILoggerProvider"/> implementation that creates loggers writing to an xUnit <see cref="IMessageSink"/>.
/// </summary>
/// <remarks>
/// This provider is intended for use in xUnit test projects to capture and forward log output to the test output stream.
/// It supports scope management and customizable log formatting via <see cref="XunitLoggerOptions"/>.
/// </remarks>
public sealed class XunitMessageSinkLoggerProvider(
    IMessageSink messageSink,
    XunitLoggerOptions? options
    ) : ILoggerProvider
{
    private readonly XunitLoggerOptions _options = options ?? new XunitLoggerOptions();
    private readonly LoggerExternalScopeProvider _scopeProvider = new();

    /// <summary>
    /// Initializes a new instance of the <see cref="XunitMessageSinkLoggerProvider"/> class with the specified <see cref="IMessageSink"/>.
    /// Uses default <see cref="XunitLoggerOptions"/>.
    /// </summary>
    /// <param name="messageSink">The xUnit message sink to which log messages will be written.</param>
    public XunitMessageSinkLoggerProvider(IMessageSink messageSink)
        : this(messageSink, options: null)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="XunitMessageSinkLoggerProvider"/> class with the specified <see cref="IMessageSink"/>
    /// and a value indicating whether to include scopes in the log output.
    /// </summary>
    /// <param name="messageSink">The xUnit message sink to which log messages will be written.</param>
    /// <param name="appendScope">If <c>true</c>, scopes will be included in the log output.</param>
    public XunitMessageSinkLoggerProvider(IMessageSink messageSink, bool appendScope)
        : this(messageSink, new XunitLoggerOptions { IncludeScopes = appendScope })
    {
    }

    /// <inheritdoc />
    public ILogger CreateLogger(string categoryName)
        => new XunitMessageSinkLogger(messageSink, _scopeProvider, categoryName, _options);

    /// <inheritdoc />
    public void Dispose() { }
}
