using System.Runtime.InteropServices;

namespace Genbox.FastCodeSignature.Internal.Native.Structs;

//https://learn.microsoft.com/en-us/windows/win32/seccrypto/signer-digest-sign-info
[StructLayout(LayoutKind.Sequential)]
internal struct SIGNER_DIGEST_SIGN_INFO(IntPtr callback, IntPtr pvOpaque)
{
    public uint cbSize = (uint)Marshal.SizeOf<SIGNER_DIGEST_SIGN_INFO>();
    public IntPtr callback = callback;
    public IntPtr pvOpaque = pvOpaque;
}