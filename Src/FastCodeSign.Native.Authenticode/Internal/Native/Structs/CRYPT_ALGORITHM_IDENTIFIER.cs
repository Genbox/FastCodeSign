using System.Runtime.InteropServices;

namespace Genbox.FastCodeSign.Internal.Native.Structs;

//https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_algorithm_identifier
[StructLayout(LayoutKind.Sequential)]
internal struct CRYPT_ALGORITHM_IDENTIFIER
{
    [MarshalAs(UnmanagedType.LPStr)]
    internal string pszObjId;
    internal CRYPT_BLOB_ARRAY Parameters;
}