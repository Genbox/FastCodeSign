using System.Text;

namespace Genbox.FastCodeSign.Internal.Helpers;

internal static class ByteHelper
{
    private static readonly byte[] Utf8Bom = [0xEF, 0xBB, 0xBF];
    private static readonly byte[] Utf16Bom = [0xFF, 0xFE];
    private static readonly byte[] Utf16BeBom = [0xFE, 0xFF];

    /// <summary>Align value up to next multiple of alignment.</summary>
    internal static ulong Align(ulong val, ulong alignment) => ((val + alignment) - 1) & ~(alignment - 1);

    internal static uint Align(uint val, uint alignment) => ((val + alignment) - 1) & ~(alignment - 1);
    internal static int Align(int val, int alignment) => ((val + alignment) - 1) & ~(alignment - 1);

    /// <summary>Padding needed to reach next multiple of alignment.</summary>
    internal static uint Pad(uint length, uint alignment) => (alignment - (length & (alignment - 1))) & (alignment - 1);

    internal static bool ContainsAdv(ReadOnlySpan<byte> span, params string[] values)
    {
        Encoding encoding = DetectEncoding(span) ?? Encoding.UTF8;

        foreach (string value in values)
        {
            byte[] encoded = encoding.GetBytes(value);
            if (span.IndexOf(encoded) >= 0)
                return true;
        }

        return false;
    }

    internal static Encoding? DetectEncoding(ReadOnlySpan<byte> data)
    {
        if (data.StartsWith(Utf8Bom))
            return Encoding.UTF8; //Does not throw on invalid bytes. We detected encoding and must respect it.

        if (data.StartsWith(Utf16Bom))
            return Encoding.Unicode;

        if (data.StartsWith(Utf16BeBom))
            return Encoding.BigEndianUnicode;

        Encoding? utf16NoBom = DetectUtf16NoBom(data);
        if (utf16NoBom != null)
            return utf16NoBom;

        return null;
    }

    private static Encoding? DetectUtf16NoBom(ReadOnlySpan<byte> data)
    {
        int pairs = Math.Min(data.Length / 2, 512);
        if (pairs < 4)
            return null;

        int leAscii = 0;
        int beAscii = 0;

        for (int i = 0; i < pairs; i++)
        {
            byte first = data[i * 2];
            byte second = data[(i * 2) + 1];

            if (second == 0 && IsLikelyTextByte(first))
                leAscii++;

            if (first == 0 && IsLikelyTextByte(second))
                beAscii++;
        }

        if (leAscii >= (pairs * 3) / 4 && beAscii == 0)
            return Encoding.Unicode;

        if (beAscii >= (pairs * 3) / 4 && leAscii == 0)
            return Encoding.BigEndianUnicode;

        return null;
    }

    private static bool IsLikelyTextByte(byte value) => value is 9 or 10 or 13 || value is >= 32 and <= 126;
}