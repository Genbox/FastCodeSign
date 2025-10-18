using System.Runtime.InteropServices;

namespace Genbox.FastCodeSign.Internal.MachObject.Headers;

// https://github.com/apple-oss-distributions/xnu/blob/e3723e1f17661b24996789d8afc084c0c3303b26/osfmk/kern/cs_blobs.h#L235
[StructLayout(LayoutKind.Sequential)]
internal readonly record struct TeamIdHeader
{
    public const int StructSize = 4;

    public required uint TeamOffset { get; init; } // offset of optional team identifier

    public void Write(Span<byte> buffer)
    {
        WriteUInt32BigEndian(buffer, TeamOffset);
    }
}