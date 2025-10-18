using Genbox.FastCodeSignature.Abstracts;

namespace Genbox.FastCodeSignature.Internal.Extensions;

internal static class AllocationExtensions
{
    internal static byte[] ToArray(this IAllocation allocation)
    {
        Span<byte> dat = allocation.GetData();
        Span<byte> ext = allocation.GetExtension();

        byte[] result = new byte[dat.Length + ext.Length];
        dat.CopyTo(result);
        ext.CopyTo(result.AsSpan(dat.Length));

        return result;
    }
}