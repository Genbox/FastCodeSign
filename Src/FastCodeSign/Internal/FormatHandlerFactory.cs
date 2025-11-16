using Genbox.FastCodeSign.Abstracts;
using Genbox.FastCodeSign.Handlers;
using Genbox.FastCodeSign.Internal.Helpers;

namespace Genbox.FastCodeSign.Internal;

internal static class FormatHandlerFactory
{
    public static IFormatHandler? Get(ReadOnlySpan<byte> span, string? ext, bool skipExtCheck)
    {
        IFormatHandler[] handlers =
        [
            new PeFormatHandler(),
            new MachObjectFormatHandler(),
            new PowerShellCmdletDefinitionXmlFormatHandler(),
            new PowerShellConsoleFormatHandler(),
            new PowerShellManifestFormatHandler(),
            new PowerShellModuleFormatHandler(),
            new PowerShellXmlFormatHandler(),
            new PowerShellScriptFormatHandler(), //This is here because it matches everything
        ];

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