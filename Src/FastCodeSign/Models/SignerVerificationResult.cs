using System.Security.Cryptography.X509Certificates;

namespace Genbox.FastCodeSign.Models;

public sealed class SignerVerificationResult
{
    internal SignerVerificationResult(X509Certificate2? certificate, CertificateTrustStatus trustStatus, IEnumerable<X509ChainStatus> chainStatuses, IEnumerable<TimestampVerificationResult> timestamps, string? diagnostic)
    {
        Certificate = certificate;
        TrustStatus = trustStatus;
        ChainStatuses = Array.AsReadOnly(chainStatuses.ToArray());
        Timestamps = Array.AsReadOnly(timestamps.ToArray());
        if (Timestamps.Count == 0)
            TimestampStatus = TimestampVerificationStatus.Absent;
        else if (Timestamps.Any(static timestamp => timestamp.Status == TimestampVerificationStatus.Trusted))
            TimestampStatus = TimestampVerificationStatus.Trusted;
        else if (Timestamps.Any(static timestamp => timestamp.Status == TimestampVerificationStatus.Untrusted))
            TimestampStatus = TimestampVerificationStatus.Untrusted;
        else
            TimestampStatus = TimestampVerificationStatus.Invalid;
        Diagnostic = diagnostic;
    }

    public X509Certificate2? Certificate { get; }
    public CertificateTrustStatus TrustStatus { get; }
    public IReadOnlyList<X509ChainStatus> ChainStatuses { get; }
    public IReadOnlyList<TimestampVerificationResult> Timestamps { get; }
    public TimestampVerificationStatus TimestampStatus { get; }
    public string? Diagnostic { get; }
}