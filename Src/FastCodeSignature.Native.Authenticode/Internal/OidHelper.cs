using System.Security.Cryptography;

namespace Genbox.FastCodeSignature.Native.Authenticode.Internal;

internal static class OidHelper
{
    //https://learn.microsoft.com/en-us/windows/win32/seccrypto/alg-id
    internal static uint HashAlgorithmToAlgId(HashAlgorithmName hash) => hash.Name switch
    {
        nameof(HashAlgorithmName.MD5) => 0x00008003,
        nameof(HashAlgorithmName.SHA1) => 0x00008004,
        nameof(HashAlgorithmName.SHA256) => 0x0000800c,
        nameof(HashAlgorithmName.SHA384) => 0x0000800d,
        nameof(HashAlgorithmName.SHA512) => 0x0000800e,
        _ => throw new NotSupportedException("The algorithm specified is not supported.")
    };

    internal static ReadOnlySpan<byte> HashAlgorithmToOidAsciiTerminated(HashAlgorithmName hash) => hash.Name switch
    {
        nameof(HashAlgorithmName.MD5) =>  "1.2.840.113549.2.5\0"u8,
        nameof(HashAlgorithmName.SHA1) => "1.3.14.3.2.26\0"u8,
        nameof(HashAlgorithmName.SHA256) => "2.16.840.1.101.3.4.2.1\0"u8,
        nameof(HashAlgorithmName.SHA384) => "2.16.840.1.101.3.4.2.2\0"u8,
        nameof(HashAlgorithmName.SHA512) => "2.16.840.1.101.3.4.2.3\0"u8,
        _ => throw new NotSupportedException("The algorithm specified is not supported.")
    };
}