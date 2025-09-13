using System.Runtime.InteropServices;
using Genbox.FastCodeSignature.Internal.Native.Enums;

namespace Genbox.FastCodeSignature.Internal.Native.Structs;

//https://learn.microsoft.com/en-us/windows/win32/seccrypto/signer-cert-store-info
[StructLayout(LayoutKind.Sequential)]
internal struct SIGNER_CERT_STORE_INFO(IntPtr pSigningCert, SIGNER_CERT_POLICY dwCertPolicy, IntPtr hCertStore)
{
    internal uint cbSize = (uint)Marshal.SizeOf<SIGNER_CERT_STORE_INFO>();
    internal IntPtr pSigningCert = pSigningCert;
    internal SIGNER_CERT_POLICY dwCertPolicy = dwCertPolicy;
    internal IntPtr hCertStore = hCertStore;
}