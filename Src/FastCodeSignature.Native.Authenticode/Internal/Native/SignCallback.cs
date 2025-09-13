using System.Runtime.InteropServices;
using Genbox.FastCodeSignature.Internal.Native.Structs;

namespace Genbox.FastCodeSignature.Internal.Native;

[UnmanagedFunctionPointer(CallingConvention.Winapi)]
internal delegate uint SignCallback(
    [MarshalAs(UnmanagedType.SysInt)]IntPtr pCertContext,
    [MarshalAs(UnmanagedType.SysInt)]IntPtr pvExtra,
    [MarshalAs(UnmanagedType.U4)]uint algId,
    [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U1, SizeParamIndex = 4)]
    byte[] pDigestToSign,
    [MarshalAs(UnmanagedType.U4)]uint dwDigestToSign,
    ref CRYPT_BLOB_ARRAY blob
);