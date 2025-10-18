using System.Runtime.InteropServices;

namespace Genbox.FastCodeSign.Internal.Native.Structs;

//https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime
[StructLayout(LayoutKind.Sequential)]
internal struct FILETIME
{
    public uint dwLowDateTime;
    public uint dwHighDateTime;
}