using System.Runtime.InteropServices;

namespace Genbox.FastCodeSign.Internal.Native.Structs;

//https://learn.microsoft.com/en-us/windows/win32/api/dpapi/ns-dpapi-crypt_integer_blob
[StructLayout(LayoutKind.Sequential)]
internal struct CRYPT_INTEGER_BLOB
{
    internal uint cbData;
    internal IntPtr pbData;
}