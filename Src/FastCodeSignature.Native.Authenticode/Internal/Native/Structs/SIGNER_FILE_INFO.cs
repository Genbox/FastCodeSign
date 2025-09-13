using System.Runtime.InteropServices;

namespace Genbox.FastCodeSignature.Internal.Native.Structs;

//https://learn.microsoft.com/en-us/windows/win32/seccrypto/signer-file-info
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct SIGNER_FILE_INFO(char* pwszFileName, IntPtr hFile)
{
    public uint cbSize = (uint)Marshal.SizeOf<SIGNER_FILE_INFO>();
    public char* pwszFileName = pwszFileName;
    public IntPtr hFile = hFile;
}