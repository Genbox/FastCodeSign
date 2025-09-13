using System.Runtime.InteropServices;

namespace Genbox.FastCodeSignature.Internal.Native.Structs;

//https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_info
[StructLayout(LayoutKind.Sequential)]
internal struct CERT_INFO
{
    internal uint dwVersion;
    internal CRYPT_INTEGER_BLOB SerialNumber;
    internal CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
    internal CRYPT_BLOB_ARRAY Issuer;
    internal FILETIME NotBefore;
    internal FILETIME NotAfter;
    internal CRYPT_BLOB_ARRAY Subject;
    internal CERT_PUBLIC_KEY_INFO SubjectPublicKeyInfo;
    internal CRYPT_BIT_BLOB IssuerUniqueId;
    internal CRYPT_BIT_BLOB SubjectUniqueId;
    internal uint cExtension;
    internal IntPtr rgExtension;
}