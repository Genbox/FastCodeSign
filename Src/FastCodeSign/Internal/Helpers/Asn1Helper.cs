namespace Genbox.FastCodeSign.Internal.Helpers;

internal static class Asn1Helper
{
    internal static byte[]? GetNullableBytes(ReadOnlySpan<byte> span)
    {
        if (span.Length == 2 && span[0] == 5 && span[1] == 0)
            return null;

        return span.ToArray();
    }
}