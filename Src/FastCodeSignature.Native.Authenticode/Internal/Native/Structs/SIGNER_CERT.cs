using System.Runtime.InteropServices;
using Genbox.FastCodeSignature.Internal.Native.Enums;
using Genbox.FastCodeSignature.Internal.Native.Unions;

namespace Genbox.FastCodeSignature.Internal.Native.Structs;

//https://learn.microsoft.com/en-us/windows/win32/seccrypto/signer-cert
[StructLayout(LayoutKind.Sequential)]
internal struct SIGNER_CERT(SIGNER_CERT_CHOICE dwCertChoice, SIGNER_CERT_UNION union)
{
    internal uint cbSize = (uint)Marshal.SizeOf<SIGNER_CERT>();
    internal SIGNER_CERT_CHOICE dwCertChoice = dwCertChoice;
    internal SIGNER_CERT_UNION Union = union;
    internal IntPtr hwnd = IntPtr.Zero;
}