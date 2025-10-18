using System.Runtime.InteropServices;

namespace Genbox.FastCodeSign.Internal.MachObject.Headers;

// https://github.com/apple-oss-distributions/xnu/blob/e3723e1f17661b24996789d8afc084c0c3303b26/osfmk/kern/cs_blobs.h#L231
[StructLayout(LayoutKind.Sequential)]
internal readonly record struct ScatterHeader
{
    public const int StructSize = 4;

    public required uint ScatterOffset { get; init; } // offset of optional scatter vector

    public void Write(Span<byte> buffer)
    {
        WriteUInt32BigEndian(buffer, ScatterOffset);
    }
}