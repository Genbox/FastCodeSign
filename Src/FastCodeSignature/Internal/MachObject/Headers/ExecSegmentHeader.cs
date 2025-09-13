using System.Runtime.InteropServices;
using Genbox.FastCodeSignature.Internal.MachObject.Headers.Enums;

namespace Genbox.FastCodeSignature.Internal.MachObject.Headers;

// https://github.com/apple-oss-distributions/xnu/blob/e3723e1f17661b24996789d8afc084c0c3303b26/osfmk/kern/cs_blobs.h#L244
[StructLayout(LayoutKind.Sequential)]
internal readonly record struct ExecSegmentHeader
{
    public const int StructSize = 24;

    public required ulong ExecSegBase { get; init; } // offset of executable segment
    public required ulong ExecSegLimit { get; init; } // limit of executable segment
    public required ExecSegFlags ExecSegFlags { get; init; } // executable segment flags

    public void Write(Span<byte> buffer)
    {
        WriteUInt64BigEndian(buffer, ExecSegBase);
        WriteUInt64BigEndian(buffer[8..], ExecSegLimit);
        WriteUInt64BigEndian(buffer[16..], (ulong)ExecSegFlags);
    }
}