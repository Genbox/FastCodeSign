using System.Text;

namespace Genbox.FastCodeSign.Handlers;

/// <summary>
/// Supports PowerShell Data files (psd1). Data files can be basic or manifest files.
/// </summary>
/// <param name="encoding">The encoding of the file. If null, automatic detection is used.</param>
public sealed class PowerShellManifestFormatHandler(Encoding? encoding = null) : TextFormatHandler("# ", "", encoding)
{
    // See:
    // - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_data_files?view=powershell-7.5
    // - https://learn.microsoft.com/en-us/powershell/scripting/developer/module/how-to-write-a-powershell-module-manifest?view=powershell-7.5

    // Smallest data file: @{AllNodes=@(@{A='B'})}
    // Smallest manifest file: @{RootModule='';ModuleVersion=''}

    public override int MinValidSize => 23;
    public override string[] ValidExt => ["psd1"];
    public override bool IsValidHeader(ReadOnlySpan<byte> data) => ContainsAdv(data, "@{");
}