using System.Diagnostics;
using System.Runtime.InteropServices;
using Genbox.FastCodeSign.Internal.MachObject.Headers.Enums;

namespace Genbox.FastCodeSign.Internal.MachObject.Headers;

// https://github.com/apple-oss-distributions/Security/blob/3dab46a11f45f2ffdbd70e2127cc5a8ce4a1f222/OSX/libsecurity_utilities/lib/blob.h#L212
[DebuggerDisplay("Type: {Type}, Length: {Length}")]
[StructLayout(LayoutKind.Sequential)]
internal readonly struct BlobWrapper
{
    internal const byte StructSize = 8;

    internal required CsMagic Type { get; init; }
    internal required uint Length { get; init; }

    // Always big endian
    internal static BlobWrapper Read(ReadOnlySpan<byte> data)
    {
        if (!BitConverter.IsLittleEndian)
            return MemoryMarshal.Read<BlobWrapper>(data);

        return new BlobWrapper
        {
            Type = (CsMagic)ReadUInt32BigEndian(data),
            Length = ReadUInt32BigEndian(data[4..])
        };
    }
}