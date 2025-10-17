using System.Security.Cryptography.Pkcs;

namespace Genbox.FastCodeSignature.Models;

public sealed class Signature
{
    internal Signature(SignedCms signedCms, object? signatureInfo)
    {
        SignedCms = signedCms;
        SignatureInfo = signatureInfo;
    }

    public SignedCms SignedCms { get; }
    internal object? SignatureInfo { get; }
}