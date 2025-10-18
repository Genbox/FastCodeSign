using System.Runtime.InteropServices;

namespace Genbox.FastCodeSign.Internal.Native.Structs;

//https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_public_key_info
[StructLayout(LayoutKind.Sequential)]
internal struct CERT_PUBLIC_KEY_INFO
{
    internal CRYPT_ALGORITHM_IDENTIFIER Algorithm;
    internal CRYPT_BIT_BLOB PublicKey;
}