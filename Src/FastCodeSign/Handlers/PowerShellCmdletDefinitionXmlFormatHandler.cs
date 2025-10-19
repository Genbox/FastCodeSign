using System.Text;

namespace Genbox.FastCodeSign.Handlers;

/// <summary>
/// Supports PowerShell Cmdlet Definition XML files (cdxml)
/// </summary>
/// <param name="encoding">The encoding of the file. If null, automatic detection is used.</param>
public sealed class PowerShellCmdletDefinitionXmlFormatHandler(Encoding? encoding = null) : TextFormatHandler("<!-- ", " -->", encoding)
{
    // See:
    // - https://learn.microsoft.com/en-us/previous-versions/windows/desktop/wmi_v2/cdxml-overview
    // - https://powershell.one/wmi/cdxml-intro

    public override int MinValidSize => 223; // <PowerShellMetadata xmlns="http://schemas.microsoft.com/cmdlets-over-objects/2009/11"><Class ClassName=""><DefaultNoun>Bios</DefaultNoun><InstanceCmdlets><GetCmdletParameters/></InstanceCmdlets></Class></PowerShellMetadata>
    public override string[] ValidExt => ["cdxml"];
    public override bool IsValidHeader(ReadOnlySpan<byte> data) => ContainsAdv(data, "PowerShellMetadata");
}