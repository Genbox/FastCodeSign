using System.Diagnostics;
using System.Runtime.InteropServices;
using Genbox.FastCodeSign.Internal.MachObject.Headers.Enums;

namespace Genbox.FastCodeSign.Internal.MachObject.Headers;

[DebuggerDisplay("Magic: {Magic}, Length: {Length}, Count: {Count}")]
[StructLayout(LayoutKind.Sequential)]
internal readonly struct SuperBlobHeader
{
    internal const byte StructSize = 12;

    internal required CsMagic Magic { get; init; }
    internal required uint Length { get; init; }
    internal required uint Count { get; init; }

    // Always big endian
    internal static SuperBlobHeader Read(ReadOnlySpan<byte> data)
    {
        if (!BitConverter.IsLittleEndian)
            return MemoryMarshal.Read<SuperBlobHeader>(data);

        return new SuperBlobHeader
        {
            Magic = (CsMagic)ReadUInt32BigEndian(data),
            Length = ReadUInt32BigEndian(data[4..]),
            Count = ReadUInt32BigEndian(data[8..])
        };
    }
}