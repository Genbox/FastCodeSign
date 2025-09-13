using System.Runtime.InteropServices;

namespace Genbox.FastCodeSignature.Internal.MachObject.Headers;

// https://github.com/apple-oss-distributions/xnu/blob/e3723e1f17661b24996789d8afc084c0c3303b26/EXTERNAL_HEADERS/mach-o/loader.h#L355
[StructLayout(LayoutKind.Auto)]
internal readonly record struct Segment
{
    internal int Offset { get; private init; }
    internal byte[] Name { get; private init; }
    internal ulong FileOffset { get; private init; }
    internal ulong FileSize { get; private init; }

    internal static Segment Read32(ReadOnlySpan<byte> data, int offset, bool le) => le ? ReadLe32(data, offset) : ReadBe32(data, offset);

    internal static Segment Read64(ReadOnlySpan<byte> data, int offset, bool le) => le ? ReadLe64(data, offset) : ReadBe64(data, offset);

    private static Segment ReadLe32(ReadOnlySpan<byte> data, int offset) => new Segment
    {
        Offset = offset - 8, //Set to start of header which include cmd and cmd size
        Name = data[..16].ToArray(),
        FileOffset = ReadUInt32LittleEndian(data[24..]),
        FileSize = ReadUInt32LittleEndian(data[28..])
    };

    private static Segment ReadBe32(ReadOnlySpan<byte> data, int offset) => new Segment
    {
        Offset = offset - 8, //Set to start of header which include cmd and cmd size
        Name = data[..16].ToArray(),
        FileOffset = ReadUInt32BigEndian(data[24..]),
        FileSize = ReadUInt32BigEndian(data[28..])
    };

    private static Segment ReadLe64(ReadOnlySpan<byte> data, int offset) => new Segment
    {
        Offset = offset - 8, //Set to start of header which include cmd and cmd size
        Name = data[..16].ToArray(),
        FileOffset = ReadUInt64LittleEndian(data[32..]),
        FileSize = ReadUInt64LittleEndian(data[40..])
    };

    private static Segment ReadBe64(ReadOnlySpan<byte> data, int offset) => new Segment
    {
        Offset = offset - 8, //Set to start of header which include cmd and cmd size
        Name = data[..16].ToArray(),
        FileOffset = ReadUInt64BigEndian(data[32..]),
        FileSize = ReadUInt64BigEndian(data[40..])
    };
}