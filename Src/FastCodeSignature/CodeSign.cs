using System.Diagnostics.CodeAnalysis;
using Genbox.FastCodeSignature.Abstracts;
using Genbox.FastCodeSignature.Internal;

namespace Genbox.FastCodeSignature;

public static class CodeSign
{
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Responsibility is delegated to CodeSignFileProvider")]
    public static CodeSignFileProvider CreateProviderFromFile(string filename, IFormatHandler handler)
    {
        FileAllocation allocation = new FileAllocation(filename);
        Span<byte> span = allocation.GetSpan();

        if (!handler.CanHandle(span, GetExt(filename)))
            throw new InvalidOperationException("Handler cannot handle the file.");

        return new CodeSignFileProvider(handler, allocation);
    }

    public static CodeSignProvider CreateProvider(IAllocation allocation, IFormatHandler handler, string? filename)
    {
        Span<byte> span = allocation.GetSpan();

        string? ext = null;
        if (filename != null)
            ext = GetExt(filename);

        if (!handler.CanHandle(span, ext))
            throw new InvalidOperationException("Handler cannot handle the file.");

        return new CodeSignProvider(handler, allocation);
    }

    private static string? GetExt(string fileName)
    {
        int idx = fileName.LastIndexOf('.');
        return idx == -1 ? null : fileName[(idx + 1)..];
    }
}