using System.Runtime.InteropServices;

namespace Genbox.FastCodeSignature.Internal.Native.Unions;

[StructLayout(LayoutKind.Explicit)]
internal unsafe struct SIGNER_CERT_UNION(void* ptr)
{
    [field: FieldOffset(0)]internal void* pwszSpcFile = ptr;
    [field: FieldOffset(0)]internal void* pCertStoreInfo = ptr;
    [field: FieldOffset(0)]internal void* pSpcChainInfo = ptr;
}