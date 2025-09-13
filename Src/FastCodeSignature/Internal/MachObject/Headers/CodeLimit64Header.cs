using System.Runtime.InteropServices;

namespace Genbox.FastCodeSignature.Internal.MachObject.Headers;

// https://github.com/apple-oss-distributions/xnu/blob/e3723e1f17661b24996789d8afc084c0c3303b26/osfmk/kern/cs_blobs.h#L239
[StructLayout(LayoutKind.Sequential)]
internal readonly record struct CodeLimit64Header
{
    public const int StructSize = 12;

    public required uint Spare3 { get; init; } // unused (must be zero)
    public required ulong CodeLimit64 { get; init; } // limit to main image signature range, 64 bits

    public void Write(Span<byte> buffer)
    {
        WriteUInt32BigEndian(buffer, Spare3);
        WriteUInt64BigEndian(buffer[4..], CodeLimit64);
    }
}