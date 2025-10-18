using System.Runtime.InteropServices;

namespace Genbox.FastCodeSign.Internal.Native.Structs;

//https://learn.microsoft.com/en-us/windows/win32/seccrypto/signer-attr-authcode
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct SIGNER_ATTR_AUTHCODE()
{
    public uint cbSize = (uint)Marshal.SizeOf<SIGNER_ATTR_AUTHCODE>();
    public uint fCommercial = 0;
    public uint fIndividual = 0;
    public IntPtr pwszName = IntPtr.Zero;
    public IntPtr pwszInfo = IntPtr.Zero;
}