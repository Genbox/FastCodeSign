using System.Text;

namespace Genbox.FastCodeSign.Handlers;

/// <summary>
/// Supports PowerShell Module files (psm1)
/// </summary>
/// <param name="encoding">The encoding of the file. If null, automatic detection is used.</param>
public sealed class PowerShellModuleFormatHandler(Encoding? encoding = null) : TextFormatHandler("# ", "", encoding)
{
    // See https://learn.microsoft.com/en-us/powershell/scripting/developer/module/understanding-a-windows-powershell-module?view=powershell-7.5

    public override int MinValidSize => 13; // function a{1}
    public override string[] ValidExt => ["psm1"];
    public override bool IsValidHeader(ReadOnlySpan<byte> data) => ContainsAdv(data, "function");
}