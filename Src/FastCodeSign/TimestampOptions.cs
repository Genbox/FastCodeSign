using System.Net.Http;
using System.Security.Cryptography;

namespace Genbox.FastCodeSign;

/// <summary>Configuration for RFC3161 timestamping.</summary>
public sealed class TimestampOptions
{
    internal const int DefaultMaximumResponseSizeBytes = 1024 * 1024;

    /// <summary>The URI of the timestamp authority.</summary>
    public required Uri TimestampAuthorityUri { get; set; }

    /// <summary>The hash algorithm used for the timestamp request.</summary>
    public HashAlgorithmName HashAlgorithm { get; set; } = HashAlgorithmName.SHA256;

    /// <summary>The HTTP client used for timestamp requests. It is not disposed by FastCodeSign.</summary>
    public HttpClient? HttpClient { get; set; }

    /// <summary>The timeout for each timestamp request, or null to rely on the HTTP client.</summary>
    public TimeSpan? Timeout { get; set; } = TimeSpan.FromSeconds(100);

    /// <summary>The maximum permitted timestamp response size in bytes.</summary>
    public int MaximumResponseSizeBytes { get; set; } = DefaultMaximumResponseSizeBytes;

    /// <summary>Gets or sets whether timestamp responses must include a Content-Type header.</summary>
    public bool RequireResponseContentType { get; set; }
}