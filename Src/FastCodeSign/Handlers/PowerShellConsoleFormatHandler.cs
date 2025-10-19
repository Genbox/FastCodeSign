using System.Text;

namespace Genbox.FastCodeSign.Handlers;

/// <summary>
/// Supports PowerShell Console files (psc1)
/// </summary>
/// <param name="encoding">The encoding of the file. If null, automatic detection is used.</param>
public sealed class PowerShellConsoleFormatHandler(Encoding? encoding = null) : TextFormatHandler("<!-- ", " -->", encoding)
{
    // See https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/export-console?view=powershell-5.1

    public override int MinValidSize => 118; // <PSConsoleFile ConsoleSchemaVersion="1.0"><PSVersion>2.0</PSVersion><PSSnapIns><PSSnapIn/></PSSnapIns></PSConsoleFile>
    public override string[] ValidExt => ["psc1"];
    public override bool IsValidHeader(ReadOnlySpan<byte> data) => ContainsAdv(data, "PSConsoleFile");
}