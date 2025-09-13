using System.Security.Cryptography;
using Genbox.FastCodeSignature.Native.Authenticode.Internal.Enums;

namespace Genbox.FastCodeSignature.Native.Authenticode;

public class TimeStampConfiguration(string url, HashAlgorithmName digestAlgorithm, TimeStampType type)
{
    /// <summary>The URL to the timestamp authority.</summary>
    public string? Url { get; } = url;

    /// <summary>The digest algorithm the timestamp service authority should use on timestamp signatures.</summary>
    public HashAlgorithmName DigestAlgorithm { get; } = digestAlgorithm;

    /// <summary>
    /// The type of timestamp to use. See <see cref="TimeStampType" /> for details, or null if
    /// no timestamping should be performed.
    /// </summary>
    public TimeStampType Type { get; } = type;
}