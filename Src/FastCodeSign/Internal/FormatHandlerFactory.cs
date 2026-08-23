using Genbox.FastCodeSign.Abstracts;
using Genbox.FastCodeSign.Handlers;

namespace Genbox.FastCodeSign.Internal;

internal static class FormatHandlerFactory
{
    private static readonly IFormatHandler[] Handlers =
    [
        new PeFormatHandler(),
        new FatMachObjectFormatHandler(),
        new MachObjectFormatHandler(),
        new PowerShellCmdletDefinitionXmlFormatHandler(),
        new PowerShellConsoleFormatHandler(),
        new PowerShellManifestFormatHandler(),
        new PowerShellXmlFormatHandler(),
        new PowerShellScriptFormatHandler(), //This is here because it matches everything
        new PowerShellModuleFormatHandler()
    ];

    public static IFormatHandler? Get(ReadOnlySpan<byte> span, string? ext, bool skipExtCheck)
    {
        foreach (IFormatHandler handler in Handlers)
        {
            if (span.Length < handler.MinValidSize)
                continue; //Too small to be valid

            if (!skipExtCheck && ext != null && handler.ValidExt.Length != 0 && !handler.ValidExt.Contains(ext))
                continue;

            if (!handler.IsValidHeader(span))
                continue;

            return handler;
        }

        return null;
    }
}