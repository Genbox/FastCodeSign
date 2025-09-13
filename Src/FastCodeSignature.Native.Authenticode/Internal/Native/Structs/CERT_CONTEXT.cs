using System.Runtime.InteropServices;

namespace Genbox.FastCodeSignature.Internal.Native.Structs;

//https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_context
[StructLayout(LayoutKind.Sequential)]
internal struct CERT_CONTEXT
{
    internal uint dwCertEncodingType;
    internal IntPtr pbCertEncoded;
    internal uint cbCertEncoded;
    internal IntPtr pCertInfo;
    internal IntPtr hCertStore;
}