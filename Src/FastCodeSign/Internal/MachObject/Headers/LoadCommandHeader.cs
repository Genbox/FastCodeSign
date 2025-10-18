using System.Runtime.InteropServices;
using Genbox.FastCodeSign.Internal.MachObject.Headers.Enums;

namespace Genbox.FastCodeSign.Internal.MachObject.Headers;

// https://github.com/apple-oss-distributions/xnu/blob/e3723e1f17661b24996789d8afc084c0c3303b26/EXTERNAL_HEADERS/mach-o/loader.h#L376
[StructLayout(LayoutKind.Sequential)]
internal readonly record struct LoadCommandHeader
{
    internal const byte StructSize = 8;

    internal required LoadCommandType Type { get; init; }
    internal required uint Size { get; init; }

    internal static LoadCommandHeader Read(ReadOnlySpan<byte> data, bool le) => le ? ReadLe(data) : ReadBe(data);

    private static LoadCommandHeader ReadLe(ReadOnlySpan<byte> data) => new LoadCommandHeader
    {
        Type = (LoadCommandType)ReadUInt32LittleEndian(data),
        Size = ReadUInt32LittleEndian(data[4..])
    };

    private static LoadCommandHeader ReadBe(ReadOnlySpan<byte> data) => new LoadCommandHeader
    {
        Type = (LoadCommandType)ReadUInt32BigEndian(data),
        Size = ReadUInt32BigEndian(data[4..])
    };
}