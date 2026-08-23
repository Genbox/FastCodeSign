using Microsoft.Win32.SafeHandles;

namespace Genbox.FastCodeSign.Internal.Native;

internal sealed class SafeCatalogHandle() : SafeHandleZeroOrMinusOneIsInvalid(true)
{
    internal SafeContextHandle ContextHandle { get; set; }

    protected override bool ReleaseHandle()
    {
        if (ContextHandle == null)
            return false;

        return Win32Native.CryptCATAdminReleaseCatalogContext(ContextHandle, handle, 0);
    }
}