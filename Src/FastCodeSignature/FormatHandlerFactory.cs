using System.Diagnostics.CodeAnalysis;
using Genbox.FastCodeSignature.Abstracts;
using Genbox.FastCodeSignature.Handlers;

namespace Genbox.FastCodeSignature;

public static class FormatHandlerFactory
{
    public static bool TryCreateFormatHandler(IAllocation allocation, [NotNullWhen(true)]out IFormatHandler? handler, string? filename = null)
    {
        IFormatHandler[] handlers =
        [
            new PeFormatHandler(),
            new MachObjectFormatHandler(null, null, null),
            new PowerShellScriptFormatHandler(null),
        ];

        ReadOnlySpan<byte> span = allocation.GetSpan();
        string? ext = Path.GetExtension(filename)?.TrimStart('.');

        foreach (IFormatHandler candidate in handlers)
        {
            if (span.Length < candidate.MinValidSize)
                continue; //Too small to be valid

            if (ext != null && !candidate.ValidExt.Contains(ext))
                continue;

            if (!candidate.IsValidHeader(span))
                continue;

            handler = candidate;
            return true;
        }

        handler = null;
        return false;
    }
}