using System.Security.Cryptography;

namespace Genbox.FastCodeSignature.Internal.Extensions;

internal static class HashAlgorithmNameExtensions
{
    internal static byte GetSize(this HashAlgorithmName hash) => hash.Name switch
    {
        "MD5" => 16,
        "SHA1" => 20,
        "SHA256" => 32,
        "SHA384" => 48,
        "SHA512" => 64,
        _ => throw new NotSupportedException($"Unsupported hash algorithm: {hash.Name}")
    };

    internal static string ToOidString(this HashAlgorithmName hash) => hash.Name switch
    {
        "MD5" => OidConstants.MD5,
        "SHA1" => OidConstants.SHA1,
        "SHA256" => OidConstants.SHA256,
        "SHA384" => OidConstants.SHA384,
        "SHA512" => OidConstants.SHA512,
        _ => throw new NotSupportedException($"Unsupported hash algorithm: {hash.Name}")
    };

    internal static Oid ToOid(this HashAlgorithmName hash) => hash.Name switch
    {
        "MD5" => new Oid(OidConstants.MD5),
        "SHA1" => new Oid(OidConstants.SHA1),
        "SHA256" => new Oid(OidConstants.SHA256),
        "SHA384" => new Oid(OidConstants.SHA384),
        "SHA512" => new Oid(OidConstants.SHA512),
        _ => throw new NotSupportedException($"Unsupported hash algorithm: {hash.Name}")
    };
}