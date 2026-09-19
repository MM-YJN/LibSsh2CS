using System.Globalization;
using System.Text;

using Microsoft.Extensions.Logging;

namespace LibSsh2CS.IntegrationTests.TestKit.Logger;

internal static class LogFormatter
{
    public static string Format(IExternalScopeProvider scopeProvider, string? categoryName, LogLevel logLevel, string message, Exception? exception, XunitLoggerOptions options)
    {
        var sb = new StringBuilder();

        if (options.TimestampFormat is not null)
        {
            DateTimeOffset now = options.UseUtcTimestamp ? DateTimeOffset.UtcNow : DateTimeOffset.Now;
            string timestamp = now.ToString(options.TimestampFormat, CultureInfo.InvariantCulture);
            sb.Append(timestamp).Append(' ');
        }

        if (options.IncludeLogLevel)
        {
            sb.Append(GetLogLevelString(logLevel)).Append(' ');
        }

        if (options.IncludeCategory)
        {
            sb.Append('[').Append(categoryName).Append("] ");
        }

        sb.Append(message);

        if (exception is not null)
        {
            sb.Append('\n').Append(exception);
        }

        // Append scopes
        if (options.IncludeScopes)
        {
            scopeProvider.ForEachScope((scope, state) =>
            {
                state.Append("\n => ");
                state.Append(scope);
            }, sb);
        }

        return sb.ToString();
    }

    private static string GetLogLevelString(LogLevel logLevel)
    {
        return logLevel switch
        {
            LogLevel.Trace => "trce",
            LogLevel.Debug => "dbug",
            LogLevel.Information => "info",
            LogLevel.Warning => "warn",
            LogLevel.Error => "fail",
            LogLevel.Critical => "crit",
            _ => throw new ArgumentOutOfRangeException(nameof(logLevel))
        };
    }
}
