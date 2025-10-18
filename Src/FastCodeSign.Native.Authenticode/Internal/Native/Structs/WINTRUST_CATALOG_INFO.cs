#nullable enable
using System.Runtime.InteropServices;

namespace Genbox.FastCodeSign.Internal.Native.Structs;

//https://learn.microsoft.com/en-us/windows/win32/api/Wintrust/ns-wintrust-wintrust_catalog_info
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 8)]
internal struct WINTRUST_CATALOG_INFO
{
    internal uint cbStruct;
    internal uint dwCatalogVersion;
    [MarshalAs(UnmanagedType.LPWStr)]
    internal string? pcwszCatalogFilePath;
    [MarshalAs(UnmanagedType.LPWStr)]
    internal string? pcwszMemberTag;
    [MarshalAs(UnmanagedType.LPWStr)]
    internal string? pcwszMemberFilePath;
    internal IntPtr hMemberFile;
    internal IntPtr pbCalculatedFileHash;
    internal uint cbCalculatedFileHash;
    internal IntPtr pcCatalogContext;
    internal IntPtr hCatAdmin;
}