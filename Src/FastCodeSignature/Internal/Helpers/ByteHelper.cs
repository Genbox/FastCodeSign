namespace Genbox.FastCodeSignature.Internal.Helpers;

internal static class ByteHelper
{
    /// <summary>Align value up to next multiple of alignment.</summary>
    internal static ulong Align(ulong val, ulong alignment) => ((val + alignment) - 1) & ~(alignment - 1);

    internal static uint Align(uint val, uint alignment) => ((val + alignment) - 1) & ~(alignment - 1);
    internal static int Align(int val, int alignment) => ((val + alignment) - 1) & ~(alignment - 1);

    /// <summary>Padding needed to reach next multiple of alignment.</summary>
    internal static uint Pad(uint length, uint alignment) => (alignment - (length & (alignment - 1))) & (alignment - 1);

    internal static uint LeftShiftData(Span<byte> buffer, uint offset, uint count)
    {
        if (offset > buffer.Length) throw new ArgumentOutOfRangeException(nameof(offset));
        if (offset + count > buffer.Length) throw new ArgumentOutOfRangeException(nameof(count));

        if (count == 0) // Do nothing
            return (uint)buffer.Length;

        if (buffer.Length == offset + count) // No shifting needed
            return (uint)buffer.Length - count;

        // Source bytes (the tail that remains after the removed block)
        Span<byte> src = buffer[(int)(offset + count)..];

        // Destination where we shift into
        Span<byte> dst = buffer.Slice((int)offset, src.Length);

        // Left-shift the data
        src.CopyTo(dst);

        // For security, we clear the old placement of the data
        buffer.Slice(buffer.Length - (int)count, (int)count).Clear();

        return count;
    }

    internal static uint RightShiftData(Span<byte> buffer, uint offset, uint count)
    {
        if (offset > buffer.Length)
            throw new ArgumentOutOfRangeException(nameof(offset));

        if (offset + count > buffer.Length)
            throw new ArgumentOutOfRangeException(nameof(count), "Not enough space in buffer to shift right by count bytes.");

        if (count == 0) // Do nothing
            return (uint)buffer.Length;

        if (buffer.Length == offset) // No shifting needed
            return (uint)buffer.Length + count;

        // Number of bytes to move = bytes from offset to end minus 'count'
        uint bytesToMove = (uint)buffer.Length - count - offset;

        // Move backwards to avoid overwriting data before it's copied
        Span<byte> src = buffer.Slice((int)offset, (int)bytesToMove);
        Span<byte> dst = buffer.Slice((int)(offset + count), (int)bytesToMove);

        // Copy backwards to handle overlap correctly
        for (int i = (int)bytesToMove - 1; i >= 0; i--)
            dst[i] = src[i];

        // For security, we clear the old placement of the data
        buffer.Slice((int)offset, (int)count).Clear();

        return count;
    }
}