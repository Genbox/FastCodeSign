using System.Diagnostics.CodeAnalysis;
using Genbox.FastCodeSignature.Abstracts;
using Genbox.FastCodeSignature.Internal;

namespace Genbox.FastCodeSignature;

public static class CodeSign
{
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Responsibility is delegated to CodeSignFileProvider")]
    public static CodeSignFileProvider CreateProviderFromFile(string filename, IFormatHandler handler, bool skipExtCheck = false)
    {
        FileAllocation allocation = new FileAllocation(filename);
        Span<byte> span = allocation.GetSpan();

        if (span.Length < handler.MinValidSize)
            throw new InvalidOperationException($"The file '{filename}' is smaller than the minimum valid size of {handler.MinValidSize} bytes");

        string? ext = skipExtCheck ? null : GetExt(filename);

        if (ext != null && handler.ValidExt.Length > 0 && !handler.ValidExt.Contains(ext))
            throw new InvalidOperationException($"Handler cannot handle the file extension {ext}");

        return new CodeSignFileProvider(handler, allocation);
    }

    public static CodeSignProvider CreateProvider(IAllocation allocation, IFormatHandler handler, string? filename = null)
    {
        Span<byte> span = allocation.GetSpan();

        if (span.Length < handler.MinValidSize)
            throw new InvalidOperationException($"The file is smaller than the minimum valid size of {handler.MinValidSize} bytes");

        string? ext = null;
        if (filename != null)
            ext = GetExt(filename);

        if (ext != null && handler.ValidExt.Length > 0 && !handler.ValidExt.Contains(ext))
            throw new InvalidOperationException($"Handler cannot handle the file extension {ext}");

        return new CodeSignProvider(handler, allocation);
    }

    private static string? GetExt(string fileName)
    {
        int idx = fileName.LastIndexOf('.');
        return idx == -1 ? null : fileName[(idx + 1)..].ToLowerInvariant();
    }
}