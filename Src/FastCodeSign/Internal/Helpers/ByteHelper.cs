using System.Text;

namespace Genbox.FastCodeSign.Internal.Helpers;

internal static class ByteHelper
{
    private static readonly byte[] Utf8Bom = [0xEF, 0xBB, 0xBF];
    private static readonly byte[] Utf16Bom = [0xFF, 0xFE];

    /// <summary>Align value up to next multiple of alignment.</summary>
    internal static ulong Align(ulong val, ulong alignment) => ((val + alignment) - 1) & ~(alignment - 1);

    internal static uint Align(uint val, uint alignment) => ((val + alignment) - 1) & ~(alignment - 1);
    internal static int Align(int val, int alignment) => ((val + alignment) - 1) & ~(alignment - 1);

    /// <summary>Padding needed to reach next multiple of alignment.</summary>
    internal static uint Pad(uint length, uint alignment) => (alignment - (length & (alignment - 1))) & (alignment - 1);

    internal static bool ContainsAdv(ReadOnlySpan<byte> array, params string[] values)
    {
        Encoding encoding = DetectEncoding(array) ?? Encoding.UTF8;
        string str = encoding.GetString(array);

        foreach (string value in values)
        {
            if (str.Contains(value))
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

        return null;
    }
}