using Microsoft.Extensions.Logging;

using Xunit.Sdk;
using Xunit.v3;

namespace LibSsh2CS.IntegrationTests.TestKit.Logger;

/// <inheritdoc />
public sealed class XunitMessageSinkLogger<T>(IMessageSink messageSink, LoggerExternalScopeProvider scopeProvider)
    : XunitMessageSinkLogger(messageSink, scopeProvider, typeof(T).FullName), ILogger<T>;

/// <summary>
/// An <see cref="ILogger"/> implementation that writes log messages to an xUnit <see cref="IMessageSink"/>.
/// </summary>
/// <remarks>
/// This logger is designed for use in xUnit test projects to capture and forward log output to the test output stream.
/// It supports scope management and customizable log formatting via <see cref="XunitLoggerOptions"/>.
/// </remarks>
public class XunitMessageSinkLogger(
    IMessageSink messageSink,
    LoggerExternalScopeProvider scopeProvider,
    string? categoryName,
    XunitLoggerOptions? options
    ) : ILogger
{
    private readonly XunitLoggerOptions _options = options ?? new();

    /// <summary>
    /// Creates a new <see cref="ILogger"/> instance that writes log messages to the specified xUnit <see cref="IMessageSink"/>.
    /// </summary>
    /// <param name="messageSink">The xUnit message sink to which log messages will be written.</param>
    /// <returns>An <see cref="ILogger"/> instance for logging to the xUnit message sink.</returns>
    public static ILogger CreateLogger(IMessageSink messageSink) => new XunitMessageSinkLogger(messageSink, new LoggerExternalScopeProvider(), "");

    /// <summary>
    /// Creates a new <see cref="ILogger{T}"/> instance that writes log messages to the specified xUnit <see cref="IMessageSink"/>.
    /// </summary>
    /// <typeparam name="T">The category type for the logger.</typeparam>
    /// <param name="messageSink">The xUnit message sink to which log messages will be written.</param>
    /// <returns>An <see cref="ILogger{T}"/> instance for logging to the xUnit message sink.</returns>
    public static ILogger<T> CreateLogger<T>(IMessageSink messageSink) => new XunitMessageSinkLogger<T>(messageSink, new LoggerExternalScopeProvider());

    /// <summary>
    /// Initializes a new instance of the <see cref="XunitMessageSinkLogger"/> class with the specified message sink, scope provider, and category name.
    /// </summary>
    /// <param name="messageSink">The xUnit message sink to which log messages will be written.</param>
    /// <param name="scopeProvider">The provider for managing logging scopes.</param>
    /// <param name="categoryName">The category name for the logger.</param>
    public XunitMessageSinkLogger(IMessageSink messageSink, LoggerExternalScopeProvider scopeProvider, string? categoryName)
        : this(messageSink, scopeProvider, categoryName, appendScope: true)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="XunitMessageSinkLogger"/> class with the specified message sink, scope provider, category name, and scope inclusion option.
    /// </summary>
    /// <param name="messageSink">The xUnit message sink to which log messages will be written.</param>
    /// <param name="scopeProvider">The provider for managing logging scopes.</param>
    /// <param name="categoryName">The category name for the logger.</param>
    /// <param name="appendScope">A value indicating whether to include scopes in the log output.</param>
    public XunitMessageSinkLogger(IMessageSink messageSink, LoggerExternalScopeProvider scopeProvider, string? categoryName, bool appendScope)
        : this(messageSink, scopeProvider, categoryName, options: new XunitLoggerOptions { IncludeScopes = appendScope })
    {
    }

    /// <inheritdoc />
    public bool IsEnabled(LogLevel logLevel) => logLevel != LogLevel.None;

    /// <inheritdoc />
    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => scopeProvider.Push(state);

    /// <inheritdoc />
    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        ArgumentNullException.ThrowIfNull(formatter);

        string message = formatter(state, exception);

        string formattedLog = LogFormatter.Format(scopeProvider, categoryName, logLevel, message, exception, _options);

        try
        {
            var diagnosticMessage = new DiagnosticMessage(formattedLog);
            messageSink.OnMessage(diagnosticMessage);
        }
        catch
        {
            // This can happen when the test is not active
        }
    }
}
