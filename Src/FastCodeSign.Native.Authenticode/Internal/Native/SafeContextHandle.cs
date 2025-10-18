using Microsoft.Win32.SafeHandles;

namespace Genbox.FastCodeSign.Internal.Native;

internal sealed class SafeContextHandle() : SafeHandleZeroOrMinusOneIsInvalid(true)
{
    protected override bool ReleaseHandle() => Win32Native.CryptCATAdminReleaseContext(handle, 0);
}