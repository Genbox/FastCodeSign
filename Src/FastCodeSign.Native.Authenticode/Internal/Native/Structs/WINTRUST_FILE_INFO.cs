using System.Runtime.InteropServices;

namespace Genbox.FastCodeSign.Internal.Native.Structs;

//https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_file_info
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct WINTRUST_FILE_INFO(string fileName)
{
    internal uint cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>();

    [MarshalAs(UnmanagedType.LPTStr)]
    internal string pcwszFilePath = fileName;
    internal IntPtr hFile = IntPtr.Zero;
    internal IntPtr pgKnownSubject = IntPtr.Zero;
}