using System.Security.Cryptography.Pkcs;

namespace Genbox.FastCodeSign.Models;

public sealed class Signature
{
    internal Signature(SignedCms signedCms, object? signatureInfo)
    {
        SignedCms = signedCms;
        SignedCmsSignatures = [signedCms];
        SignatureInfo = signatureInfo;
    }

    internal Signature(SignedCms signedCms, IReadOnlyList<SignedCms> signedCmsSignatures, object? signatureInfo)
    {
        SignedCms = signedCms;
        SignedCmsSignatures = signedCmsSignatures;
        SignatureInfo = signatureInfo;
    }

    public SignedCms SignedCms { get; }

    /// <summary>
    /// Contains one CMS per signed architecture. For non-universal formats this contains <see cref="SignedCms" /> only.
    /// </summary>
    public IReadOnlyList<SignedCms> SignedCmsSignatures { get; }

    internal object? SignatureInfo { get; }
}