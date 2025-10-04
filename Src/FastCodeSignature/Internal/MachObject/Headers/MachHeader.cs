using System.Runtime.InteropServices;
using Genbox.FastCodeSignature.Internal.MachObject.Headers.Enums;

namespace Genbox.FastCodeSignature.Internal.MachObject.Headers;

// https://github.com/apple-oss-distributions/xnu/blob/e3723e1f17661b24996789d8afc084c0c3303b26/EXTERNAL_HEADERS/mach-o/loader.h#L72C13-L72C21
[StructLayout(LayoutKind.Auto)]
internal readonly ref struct MachHeader
{
    internal const byte StructSize32 = 24;
    internal const byte StructSize64 = 28;

    internal required uint NumberOfCommands { get; init; }
    internal required uint SizeOfCommands { get; init; }

    internal static MachHeader Read(ReadOnlySpan<byte> data, bool le) => le ? ReadLe(data) : ReadBe(data);

    private static MachHeader ReadLe(ReadOnlySpan<byte> data) => new MachHeader
    {
        NumberOfCommands = ReadUInt32LittleEndian(data[12..]),
        SizeOfCommands = ReadUInt32LittleEndian(data[16..])
    };

    private static MachHeader ReadBe(ReadOnlySpan<byte> data) => new MachHeader
    {
        NumberOfCommands = ReadUInt32BigEndian(data[12..]),
        SizeOfCommands = ReadUInt32BigEndian(data[16..])
    };
}