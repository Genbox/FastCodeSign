using System.Runtime.InteropServices;
using Genbox.FastCodeSignature.Internal.Native.Enums;

namespace Genbox.FastCodeSignature.Internal.Native.Structs;

//https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-crypt_provider_cert
[StructLayout(LayoutKind.Sequential)]
internal struct CRYPT_PROVIDER_CERT
{
    internal uint cbStruct;
    internal IntPtr pCert;
    [MarshalAs(UnmanagedType.Bool)]
    internal bool fCommercial;
    [MarshalAs(UnmanagedType.Bool)]
    internal bool fTrustedRoot;
    [MarshalAs(UnmanagedType.Bool)]
    internal bool fSelfSigned;
    [MarshalAs(UnmanagedType.Bool)]
    internal bool fTestCert;
    internal uint dwRevokedReason;
    internal CERT_CONFIDENCE dwConfidence;
    internal uint dwError;
    internal IntPtr pTrustListContext;
    [MarshalAs(UnmanagedType.Bool)]
    internal bool fTrustListSignerCert;
    internal IntPtr pCtlContext;
    internal uint dwCtlError;
    [MarshalAs(UnmanagedType.Bool)]
    internal bool fIsCyclic;
    internal IntPtr pChainElement;
}