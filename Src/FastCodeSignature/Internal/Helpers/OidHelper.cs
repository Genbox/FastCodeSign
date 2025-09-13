using System.Security.Cryptography;

namespace Genbox.FastCodeSignature.Internal.Helpers;

internal static class OidHelper
{
    internal static HashAlgorithmName OidToHashAlgorithm(string oid) => oid switch
    {
        OidConstants.MD5 => HashAlgorithmName.MD5,
        OidConstants.SHA1 => HashAlgorithmName.SHA1,
        OidConstants.SHA256 => HashAlgorithmName.SHA256,
        OidConstants.SHA384 => HashAlgorithmName.SHA384,
        OidConstants.SHA512 => HashAlgorithmName.SHA512,
        _ => throw new NotSupportedException($"Unsupported hash algorithm: {oid}")
    };
}