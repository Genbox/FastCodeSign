using System.Runtime.InteropServices;

namespace Genbox.FastCodeSignature.Internal.Native.Structs;

//https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_blob_array
[StructLayout(LayoutKind.Sequential)]
internal struct CRYPT_BLOB_ARRAY
{
    internal uint cbData;
    internal IntPtr pbData;
}