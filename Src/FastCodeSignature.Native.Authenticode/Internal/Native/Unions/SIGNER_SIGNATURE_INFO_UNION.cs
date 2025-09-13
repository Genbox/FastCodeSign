using System.Runtime.InteropServices;
using Genbox.FastCodeSignature.Internal.Native.Structs;

namespace Genbox.FastCodeSignature.Internal.Native.Unions;

[StructLayout(LayoutKind.Explicit)]
internal unsafe struct SIGNER_SIGNATURE_INFO_UNION(SIGNER_ATTR_AUTHCODE* pAttrAuthcode)
{
    [field: FieldOffset(0)]
    public SIGNER_ATTR_AUTHCODE* pAttrAuthcode = pAttrAuthcode;
}