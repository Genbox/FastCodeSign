using System.Runtime.InteropServices;

namespace Genbox.FastCodeSign.Internal.Native.Structs;

//https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-crypt_provider_sgnr
[StructLayout(LayoutKind.Sequential)]
internal struct CRYPT_PROVIDER_SGNR
{
    internal uint cbStruct;
    internal FILETIME sftVerifyAsOf;
    internal uint csCertChain;
    internal IntPtr pasCertChain;
    internal uint dwSignerType;
    internal IntPtr psSigner;
    internal uint dwError;
    internal uint csCounterSigners;
    internal IntPtr pasCounterSigners;
    internal IntPtr pChainContext;
}