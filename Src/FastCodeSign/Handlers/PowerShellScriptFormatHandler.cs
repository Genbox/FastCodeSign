using System.Text;

namespace Genbox.FastCodeSign.Handlers;

/// <summary>
/// Supports PowerShell script files (ps1)
/// </summary>
/// <param name="encoding">The encoding of the file. If null, automatic detection is used.</param>
public sealed class PowerShellScriptFormatHandler(Encoding? encoding = null) : TextFormatHandler("# ", "", encoding)
{
    // See: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_scripts?view=powershell-7.5

    public override int MinValidSize => 0; //An empty PS1 file is valid
    public override string[] ValidExt => ["ps1"];
    public override bool IsValidHeader(ReadOnlySpan<byte> data) => true;
}