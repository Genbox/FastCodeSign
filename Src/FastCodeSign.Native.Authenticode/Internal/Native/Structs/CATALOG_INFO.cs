using System.Runtime.InteropServices;

namespace Genbox.FastCodeSign.Internal.Native.Structs;

//https://learn.microsoft.com/en-us/windows/win32/api/mscat/ns-mscat-catalog_info
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct CATALOG_INFO()
{
    internal uint cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>();

    // Fixed-size buffer of WCHARs (MAX_PATH = 260)
    private unsafe fixed char _wszCatalogFile[260];

    // Expose as a managed string accessor
    public unsafe string wszCatalogFile
    {
        get
        {
            fixed (char* p = _wszCatalogFile)
                return new string(p);
        }
    }
}