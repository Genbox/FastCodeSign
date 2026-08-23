using System.Security.Cryptography.X509Certificates;

namespace Genbox.FastCodeSign;

/// <summary>Configures managed certificate-chain verification for code signatures.</summary>
public sealed class CodeSignVerificationOptions
{
    private IReadOnlyList<X509Certificate2> _customTrustRoots = Array.AsReadOnly(Array.Empty<X509Certificate2>());
    private IReadOnlyList<string> _applicationPolicyOids = Array.AsReadOnly(new[] { "1.3.6.1.5.5.7.3.3" });

    /// <summary>Gets or sets the time used when no trusted RFC3161 timestamp is used.</summary>
    public DateTime? VerificationTime { get; init; }
    public X509RevocationMode RevocationMode { get; init; } = X509RevocationMode.Online;
    public X509RevocationFlag RevocationFlag { get; init; } = X509RevocationFlag.ExcludeRoot;
    public X509ChainTrustMode TrustMode { get; init; } = X509ChainTrustMode.System;

    /// <summary>Gets or sets the custom roots used when <see cref="TrustMode"/> is <see cref="X509ChainTrustMode.CustomRootTrust"/>.</summary>
    public IEnumerable<X509Certificate2> CustomTrustRoots
    {
        get => _customTrustRoots;
        init => _customTrustRoots = Array.AsReadOnly((value ?? Array.Empty<X509Certificate2>()).ToArray());
    }

    /// <summary>Gets or sets EKU OIDs required on signing certificates. Defaults to code signing.</summary>
    public IEnumerable<string> ApplicationPolicyOids
    {
        get => _applicationPolicyOids;
        init => _applicationPolicyOids = Array.AsReadOnly((value ?? Array.Empty<string>()).ToArray());
    }

    /// <summary>Gets or sets whether a trusted RFC3161 timestamp determines the signing certificate validation time.</summary>
    public bool UseTimestampTime { get; init; } = true;
}