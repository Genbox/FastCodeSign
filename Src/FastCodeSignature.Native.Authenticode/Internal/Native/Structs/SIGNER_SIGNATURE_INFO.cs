using System.Runtime.InteropServices;
using Genbox.FastCodeSignature.Internal.Native.Enums;
using Genbox.FastCodeSignature.Internal.Native.Unions;

namespace Genbox.FastCodeSignature.Internal.Native.Structs;

//https://learn.microsoft.com/en-us/windows/win32/seccrypto/signer-signature-info
[StructLayout(LayoutKind.Sequential)]
internal struct SIGNER_SIGNATURE_INFO(uint algidHash, SIGNER dwAttrChoice, SIGNER_SIGNATURE_INFO_UNION attrAuthUnion)
{
    public uint cbSize = (uint)Marshal.SizeOf<SIGNER_SIGNATURE_INFO>();
    public uint algidHash = algidHash;
    public SIGNER dwAttrChoice = dwAttrChoice;
    public SIGNER_SIGNATURE_INFO_UNION attrAuthUnion = attrAuthUnion;
    public IntPtr psAuthenticated = IntPtr.Zero;
    public IntPtr psUnauthenticated = IntPtr.Zero;
}