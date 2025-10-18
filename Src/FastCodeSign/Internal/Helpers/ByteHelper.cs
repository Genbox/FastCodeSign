namespace Genbox.FastCodeSign.Internal.Helpers;

internal static class ByteHelper
{
    /// <summary>Align value up to next multiple of alignment.</summary>
    internal static ulong Align(ulong val, ulong alignment) => ((val + alignment) - 1) & ~(alignment - 1);

    internal static uint Align(uint val, uint alignment) => ((val + alignment) - 1) & ~(alignment - 1);
    internal static int Align(int val, int alignment) => ((val + alignment) - 1) & ~(alignment - 1);

    /// <summary>Padding needed to reach next multiple of alignment.</summary>
    internal static uint Pad(uint length, uint alignment) => (alignment - (length & (alignment - 1))) & (alignment - 1);
}