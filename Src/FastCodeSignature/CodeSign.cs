using Genbox.FastCodeSignature.Abstracts;
using Genbox.FastCodeSignature.Internal;

namespace Genbox.FastCodeSignature;

public static class CodeSign
{
    public static CodeSignProvider CreateProvider(string file, IFormatHandler handler)
    {
        MmfAllocation allocation = new MmfAllocation(file);
        Span<byte> span = allocation.GetSpan();

        if (!handler.CanHandle(span, GetExt(file)))
            throw new InvalidOperationException("Handler cannot handle the file.");

        return new CodeSignProvider(handler, allocation);
    }

    public static CodeSignProvider CreateProvider(Memory<byte> data, IFormatHandler handler)
    {
        MemoryAllocation allocation = new MemoryAllocation(data);
        Span<byte> span = allocation.GetSpan();

        if (!handler.CanHandle(span, null))
            throw new InvalidOperationException("Handler cannot handle the file.");

        return new CodeSignProvider(handler, allocation);
    }

    private static string? GetExt(string fileName)
    {
        int idx = fileName.LastIndexOf('.');
        return idx == -1 ? null : fileName[(idx + 1)..];
    }
}