using System.Runtime.InteropServices;

namespace Genbox.FastCodeSignature.Internal.Native.Structs;

//https://learn.microsoft.com/en-us/windows/win32/appxpkg/how-to-programmatically-sign-a-package
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct APPX_SIP_CLIENT_DATA(SIGNER_SIGN_EX3_PARAMS* pSignerParams)
{
    public SIGNER_SIGN_EX3_PARAMS* pSignerParams = pSignerParams;
    public IntPtr pAppxSipState = IntPtr.Zero;
}