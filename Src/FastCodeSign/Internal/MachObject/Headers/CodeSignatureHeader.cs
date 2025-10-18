using System.Runtime.InteropServices;

namespace Genbox.FastCodeSign.Internal.MachObject.Headers;

[StructLayout(LayoutKind.Sequential)]
internal sealed class CodeSignatureHeader
{
    internal const byte StructSize = 8;

    internal required int Offset { get; init; }
    internal required uint DataOffset { get; init; }
    internal required uint DataSize { get; init; }

    internal static CodeSignatureHeader Read(ReadOnlySpan<byte> data, int offset, bool le) => le ? ReadLe(data, offset) : ReadBe(data, offset);

    private static CodeSignatureHeader ReadLe(ReadOnlySpan<byte> data, int offset) => new CodeSignatureHeader
    {
        Offset = offset,
        DataOffset = ReadUInt32LittleEndian(data),
        DataSize = ReadUInt32LittleEndian(data[4..])
    };

    private static CodeSignatureHeader ReadBe(ReadOnlySpan<byte> data, int offset) => new CodeSignatureHeader
    {
        Offset = offset,
        DataOffset = ReadUInt32BigEndian(data),
        DataSize = ReadUInt32BigEndian(data[4..])
    };
}