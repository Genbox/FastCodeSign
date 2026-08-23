namespace Genbox.FastCodeSign.Models;

/// <summary>Contains integrity and managed certificate-chain verification results for every CMS signer.</summary>
public sealed class CodeSignVerificationResult
{
    internal CodeSignVerificationResult(SignatureIntegrityStatus integrityStatus, CertificateTrustStatus trustStatus, IEnumerable<SignerVerificationResult> signers, string? diagnostic)
    {
        IntegrityStatus = integrityStatus;
        TrustStatus = trustStatus;
        Signers = Array.AsReadOnly(signers.ToArray());
        Diagnostic = diagnostic;
    }

    /// <summary>Gets whether the signature verifies against the format-specific signed content and digest.</summary>
    public SignatureIntegrityStatus IntegrityStatus { get; }

    /// <summary>Gets the aggregate managed certificate-chain status for all CMS signers.</summary>
    public CertificateTrustStatus TrustStatus { get; }

    public IReadOnlyList<SignerVerificationResult> Signers { get; }
    public string? Diagnostic { get; }
    public bool Success => IntegrityStatus == SignatureIntegrityStatus.Valid && TrustStatus == CertificateTrustStatus.Trusted;
}