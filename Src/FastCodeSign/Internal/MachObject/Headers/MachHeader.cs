using System.Runtime.InteropServices;
using static Genbox.FastCodeSign.Internal.MachObject.MachBinaryPrimitives;

namespace Genbox.FastCodeSign.Internal.MachObject.Headers;

// https://github.com/apple-oss-distributions/xnu/blob/e3723e1f17661b24996789d8afc084c0c3303b26/EXTERNAL_HEADERS/mach-o/loader.h#L72C13-L72C21
[StructLayout(LayoutKind.Auto)]
internal readonly struct MachHeader
{
    internal const byte StructSize32 = 24;
    internal const byte StructSize64 = 28;

    internal required uint NumberOfCommands { get; init; }
    internal required uint SizeOfCommands { get; init; }

    internal static MachHeader Read(ReadOnlySpan<byte> data, bool le) => new MachHeader
    {
        NumberOfCommands = ReadU32(data[12..], le),
        SizeOfCommands = ReadU32(data[16..], le)
    };
}