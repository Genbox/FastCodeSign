using System.Runtime.CompilerServices;

namespace Genbox.FastCodeSign.Internal.MachObject;

internal static class MachBinaryPrimitives
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static uint ReadU32(ReadOnlySpan<byte> span, bool le) => le ? ReadUInt32LittleEndian(span) : ReadUInt32BigEndian(span);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static ulong ReadU64(ReadOnlySpan<byte> span, bool le) => le ? ReadUInt64LittleEndian(span) : ReadUInt64BigEndian(span);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static void WriteU32(Span<byte> span, uint value, bool le)
    {
        if (le)
            WriteUInt32LittleEndian(span, value);
        else
            WriteUInt32BigEndian(span, value);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static void WriteU64(Span<byte> span, ulong value, bool le)
    {
        if (le)
            WriteUInt64LittleEndian(span, value);
        else
            WriteUInt64BigEndian(span, value);
    }
}