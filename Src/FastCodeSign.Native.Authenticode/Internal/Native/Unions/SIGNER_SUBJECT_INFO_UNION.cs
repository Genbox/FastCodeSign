using System.Runtime.InteropServices;
using Genbox.FastCodeSign.Internal.Native.Structs;

namespace Genbox.FastCodeSign.Internal.Native.Unions;

[StructLayout(LayoutKind.Explicit)]
internal unsafe struct SIGNER_SUBJECT_INFO_UNION(SIGNER_FILE_INFO* file)
{
    [FieldOffset(0)]
    public SIGNER_FILE_INFO* file = file;
}