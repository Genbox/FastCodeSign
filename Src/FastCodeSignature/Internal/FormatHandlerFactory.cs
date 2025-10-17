using Genbox.FastCodeSignature.Abstracts;
using Genbox.FastCodeSignature.Handlers;
using Genbox.FastCodeSignature.Internal.Helpers;

namespace Genbox.FastCodeSignature.Internal;

internal static class FormatHandlerFactory
{
    public static IFormatHandler? Get(ReadOnlySpan<byte> span, string? fileName, bool skipExtCheck)
    {
        IFormatHandler[] handlers =
        [
            new PeFormatHandler(),
            new MachObjectFormatHandler(fileName!),
            new PowerShellScriptFormatHandler(), //This is here because it is more likely to be chosen
            new PowerShellCmdletDefinitionXmlFormatHandler(),
            new PowerShellConsoleFormatHandler(),
            new PowerShellManifestFormatHandler(),
            new PowerShellModuleFormatHandler(),
            new PowerShellXmlFormatHandler()
        ];

        string? ext = fileName == null ? null : PathHelper.GetExt(fileName);

        foreach (IFormatHandler handler in handlers)
        {
            if (span.Length < handler.MinValidSize)
                continue; //Too small to be valid

            if (!skipExtCheck && ext != null && !handler.ValidExt.Contains(ext))
                continue;

            if (!handler.IsValidHeader(span))
                continue;

            return handler;
        }

        return null;
    }
}