using System.Runtime.InteropServices;
using static Genbox.FastCodeSign.Internal.MachObject.MachBinaryPrimitives;

namespace Genbox.FastCodeSign.Internal.MachObject.Headers;

[StructLayout(LayoutKind.Sequential)]
internal sealed class CodeSignatureHeader
{
    internal const byte StructSize = 8;

    internal required int Offset { get; init; }
    internal required uint DataOffset { get; init; }
    internal required uint DataSize { get; init; }

    internal static CodeSignatureHeader Read(ReadOnlySpan<byte> data, int offset, bool le) => new CodeSignatureHeader
    {
        Offset = offset,
        DataOffset = ReadU32(data, le),
        DataSize = ReadU32(data[4..], le)
    };
}