using System.Security.Cryptography.Pkcs;

namespace Genbox.FastCodeSignature;

public class Signature
{
    internal Signature(SignedCms signedCms, object? signatureInfo)
    {
        SignedCms = signedCms;
        SignatureInfo = signatureInfo;
    }

    public SignedCms SignedCms { get; }
    internal object? SignatureInfo { get; }
}