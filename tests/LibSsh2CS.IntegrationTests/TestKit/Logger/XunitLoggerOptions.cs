using System.Diagnostics.CodeAnalysis;

namespace LibSsh2CS.IntegrationTests.TestKit.Logger;

/// <summary>
/// Provides configuration options for the xUnit logger used in test helpers.
/// </summary>
/// <remarks>
/// Allows customization of log output, including scopes, categories, log levels, and timestamp formatting.
/// </remarks>
public sealed class XunitLoggerOptions
{
    /// <summary>
    /// Gets or sets a value indicating whether scopes should be included in the log output.
    /// </summary>
    public bool IncludeScopes { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the log category should be included in the log output.
    /// </summary>
    public bool IncludeCategory { get; set; } = true;

    /// <summary>
    /// Gets or sets a value indicating whether the log level should be included in the log output.
    /// </summary>
    public bool IncludeLogLevel { get; set; } = true;

    /// <summary>
    /// Gets or sets the format string used to format timestamps in logging messages.
    /// Defaults to <see langword="null" />.
    /// </summary>
    [StringSyntax(StringSyntaxAttribute.DateTimeFormat)]
    public string? TimestampFormat { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether UTC timezone should be used to format timestamps in logging messages.
    /// Defaults to <see langword="true" />.
    /// </summary>
    public bool UseUtcTimestamp { get; set; } = true;
}
