using System.Runtime.InteropServices;

namespace Genbox.FastCodeSign.Internal.Native.Structs;

//https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_bit_blob
[StructLayout(LayoutKind.Sequential)]
internal struct CRYPT_BIT_BLOB
{
    internal uint cbData;
    internal IntPtr pbData;
    internal uint cUnusedBits;
}