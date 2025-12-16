using System.Runtime.InteropServices;
using static Genbox.FastCodeSign.Internal.MachObject.MachBinaryPrimitives;

namespace Genbox.FastCodeSign.Internal.MachObject.Headers;

// https://github.com/apple-oss-distributions/xnu/blob/e3723e1f17661b24996789d8afc084c0c3303b26/EXTERNAL_HEADERS/mach-o/loader.h#L355
[StructLayout(LayoutKind.Auto)]
internal sealed class Segment
{
    internal required int Offset { get; init; }
    internal required byte[] Name { get; init; }
    internal required ulong FileOffset { get; init; }
    internal required ulong FileSize { get; init; }

    internal static Segment Read32(ReadOnlySpan<byte> data, int offset, bool le) => new Segment
    {
        Offset = offset - 8, //Set to start of header which include cmd and cmd size
        Name = data[..16].ToArray(),
        FileOffset = ReadU32(data[24..], le),
        FileSize = ReadU32(data[28..], le)
    };

    internal static Segment Read64(ReadOnlySpan<byte> data, int offset, bool le) => new Segment
    {
        Offset = offset - 8, //Set to start of header which include cmd and cmd size
        Name = data[..16].ToArray(),
        FileOffset = ReadU64(data[32..], le),
        FileSize = ReadU64(data[40..], le)
    };
}