using Microsoft.Win32.SafeHandles;

namespace Genbox.FastCodeSignature.Internal.Native;

internal sealed class SafeCatalogHandle() : SafeHandleZeroOrMinusOneIsInvalid(true)
{
    internal SafeContextHandle ContextHandle { get; set; }

    protected override bool ReleaseHandle()
    {
        if (ContextHandle == null)
            throw new InvalidOperationException("ContextHandle is null. This should not happen.");

        return Win32Native.CryptCATAdminReleaseCatalogContext(ContextHandle, handle, 0);
    }
}