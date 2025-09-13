using System.Runtime.InteropServices;
using Genbox.FastCodeSignature.Internal.Native.Enums;
using Genbox.FastCodeSignature.Internal.Native.Unions;

namespace Genbox.FastCodeSignature.Internal.Native.Structs;

//https://learn.microsoft.com/en-us/windows/win32/seccrypto/signer-subject-info
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct SIGNER_SUBJECT_INFO(uint* pdwIndex, SIGNER_SUBJECT dwSubjectChoice, SIGNER_SUBJECT_INFO_UNION unionInfo)
{
    public uint cbSize = (uint)Marshal.SizeOf<SIGNER_SUBJECT_INFO>();
    public uint* pdwIndex = pdwIndex;
    public SIGNER_SUBJECT dwSubjectChoice = dwSubjectChoice;
    public SIGNER_SUBJECT_INFO_UNION unionInfo = unionInfo;
}