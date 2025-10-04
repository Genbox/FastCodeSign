using System.Diagnostics;
using System.Runtime.InteropServices;
using Genbox.FastCodeSignature.Internal.MachObject.Headers.Enums;

namespace Genbox.FastCodeSignature.Internal.MachObject.Headers;

// https://github.com/apple-oss-distributions/Security/blob/3dab46a11f45f2ffdbd70e2127cc5a8ce4a1f222/OSX/libsecurity_codesigning/lib/cscdefs.h#L18
[DebuggerDisplay("Type: {Type}, Offset: {Offset}")]
[StructLayout(LayoutKind.Sequential)]
internal readonly struct BlobIndex
{
    internal const byte StructSize = 8;

    internal required CsSlot Type { get; init; }
    internal required uint Offset { get; init; }

    // Always big endian
    internal static BlobIndex Read(ReadOnlySpan<byte> data)
    {
        if (!BitConverter.IsLittleEndian)
            return MemoryMarshal.Read<BlobIndex>(data);

        return new BlobIndex
        {
            Type = (CsSlot)ReadUInt32BigEndian(data),
            Offset = ReadUInt32BigEndian(data[4..])
        };
    }
}