using Microsoft.Extensions.Logging;

namespace LibSsh2CS.IntegrationTests.TestKit.Logger;

/// <summary>
/// Provides an <see cref="ILoggerProvider"/> implementation that creates loggers writing to xUnit's <see cref="ITestOutputHelper"/>.
/// </summary>
/// <remarks>
/// This provider is intended for use in xUnit test projects to capture log output and display it in test results.
/// It supports configuration via <see cref="XunitLoggerOptions"/> and can include scopes and categories in the log output.
/// </remarks>
public sealed class XunitTestOutputLoggerProvider(
    ITestOutputHelper testOutputHelper,
    XunitLoggerOptions? options
    ) : ILoggerProvider
{
    private readonly XunitLoggerOptions _options = options ?? new XunitLoggerOptions();
    private readonly LoggerExternalScopeProvider _scopeProvider = new();

    /// <summary>
    /// Initializes a new instance of the <see cref="XunitTestOutputLoggerProvider"/> class with default options.
    /// </summary>
    /// <param name="testOutputHelper">The xUnit test output helper to write log messages to.</param>
    public XunitTestOutputLoggerProvider(ITestOutputHelper testOutputHelper)
        : this(testOutputHelper, options: null)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="XunitTestOutputLoggerProvider"/> class with an option to include scopes in the log output.
    /// </summary>
    /// <param name="testOutputHelper">The xUnit test output helper to write log messages to.</param>
    /// <param name="appendScope">If set to <c>true</c>, includes scopes in the log output.</param>
    public XunitTestOutputLoggerProvider(ITestOutputHelper testOutputHelper, bool appendScope)
        : this(testOutputHelper, new XunitLoggerOptions { IncludeScopes = appendScope })
    {
    }

    /// <inheritdoc />
    public ILogger CreateLogger(string categoryName)
        => new XunitTestOutputLogger(testOutputHelper, _scopeProvider, categoryName, _options);

    /// <inheritdoc />
    public void Dispose() { }
}
