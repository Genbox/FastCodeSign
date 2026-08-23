using System.Security.Cryptography.X509Certificates;

namespace Genbox.FastCodeSign.Models;

public sealed class TimestampVerificationResult
{
    internal TimestampVerificationResult(TimestampVerificationStatus status, DateTimeOffset? timestamp, X509Certificate2? certificate, IEnumerable<X509ChainStatus> chainStatuses, string? diagnostic)
    {
        Status = status;
        Timestamp = timestamp;
        Certificate = certificate;
        ChainStatuses = Array.AsReadOnly(chainStatuses.ToArray());
        Diagnostic = diagnostic;
    }

    public TimestampVerificationStatus Status { get; }
    public DateTimeOffset? Timestamp { get; }
    public X509Certificate2? Certificate { get; }
    public IReadOnlyList<X509ChainStatus> ChainStatuses { get; }
    public string? Diagnostic { get; }
}