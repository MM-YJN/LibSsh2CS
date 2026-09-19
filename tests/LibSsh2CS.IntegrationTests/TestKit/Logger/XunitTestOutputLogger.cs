using Microsoft.Extensions.Logging;

namespace LibSsh2CS.IntegrationTests.TestKit.Logger;

/// <inheritdoc />
public sealed class XunitTestOutputLogger<T>(ITestOutputHelper testOutputHelper, LoggerExternalScopeProvider scopeProvider)
    : XunitTestOutputLogger(testOutputHelper, scopeProvider, typeof(T).FullName), ILogger<T>;

/// <summary>
/// An xUnit logger implementation that writes log messages to the test output.
/// </summary>
/// <remarks>
/// This logger is intended for use within xUnit test projects. It formats log messages and writes them to the
/// <see cref="ITestOutputHelper"/> output stream, making them visible in test results. Supports scopes, categories,
/// and custom formatting via <see cref="XunitLoggerOptions"/>.
/// </remarks>
public class XunitTestOutputLogger(
    ITestOutputHelper testOutputHelper,
    LoggerExternalScopeProvider scopeProvider,
    string? categoryName,
    XunitLoggerOptions? options
    ) : ILogger
{
    private readonly ITestOutputHelper _testOutputHelper = testOutputHelper;
    private readonly string? _categoryName = categoryName;
    private readonly XunitLoggerOptions _options = options ?? new();
    private readonly LoggerExternalScopeProvider _scopeProvider = scopeProvider;

    /// <summary>
    /// Creates a new <see cref="ILogger"/> instance that writes log messages to the xUnit test output.
    /// </summary>
    /// <param name="testOutputHelper">The xUnit test output helper to write log messages to.</param>
    /// <returns>An <see cref="ILogger"/> instance for use in tests.</returns>
    public static ILogger CreateLogger(ITestOutputHelper testOutputHelper) => new XunitTestOutputLogger(testOutputHelper, new LoggerExternalScopeProvider(), "");

    /// <summary>
    /// Creates a new <see cref="ILogger{T}"/> instance that writes log messages to the xUnit test output.
    /// </summary>
    /// <typeparam name="T">The category type for the logger.</typeparam>
    /// <param name="testOutputHelper">The xUnit test output helper to write log messages to.</param>
    /// <returns>An <see cref="ILogger{T}"/> instance for use in tests.</returns>
    public static ILogger<T> CreateLogger<T>(ITestOutputHelper testOutputHelper) => new XunitTestOutputLogger<T>(testOutputHelper, new LoggerExternalScopeProvider());

    /// <summary>
    /// Initializes a new instance of the <see cref="XunitTestOutputLogger"/> class with the specified test output helper, scope provider, and category name.
    /// Scopes are included in the log output by default.
    /// </summary>
    /// <param name="testOutputHelper">The xUnit test output helper to write log messages to.</param>
    /// <param name="scopeProvider">The scope provider for managing log scopes.</param>
    /// <param name="categoryName">The category name for the logger.</param>
    public XunitTestOutputLogger(ITestOutputHelper testOutputHelper, LoggerExternalScopeProvider scopeProvider, string? categoryName)
        : this(testOutputHelper, scopeProvider, categoryName, appendScope: true)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="XunitTestOutputLogger"/> class with the specified test output helper, scope provider, category name, and scope inclusion option.
    /// </summary>
    /// <param name="testOutputHelper">The xUnit test output helper to write log messages to.</param>
    /// <param name="scopeProvider">The scope provider for managing log scopes.</param>
    /// <param name="categoryName">The category name for the logger.</param>
    /// <param name="appendScope">Whether to include scopes in the log output.</param>
    public XunitTestOutputLogger(ITestOutputHelper testOutputHelper, LoggerExternalScopeProvider scopeProvider, string? categoryName, bool appendScope)
        : this(testOutputHelper, scopeProvider, categoryName, options: new XunitLoggerOptions { IncludeScopes = appendScope })
    {
    }

    /// <inheritdoc />
    public bool IsEnabled(LogLevel logLevel) => logLevel != LogLevel.None;

    /// <inheritdoc />
    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => _scopeProvider.Push(state);

    /// <inheritdoc />
    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        ArgumentNullException.ThrowIfNull(formatter);

        string message = formatter(state, exception);

        string formattedLog = LogFormatter.Format(_scopeProvider, _categoryName, logLevel, message, exception, _options);

        try
        {
            _testOutputHelper.WriteLine(formattedLog);
        }
        catch
        {
            // This can happen when the test is not active
        }
    }
}
