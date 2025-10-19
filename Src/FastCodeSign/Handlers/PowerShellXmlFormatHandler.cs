using System.Text;

namespace Genbox.FastCodeSign.Handlers;

/// <summary>
/// Supports PowerShell object format/type definition files (ps1xml)
/// </summary>
/// <param name="encoding">The encoding of the file. If null, automatic detection is used.</param>
public sealed class PowerShellXmlFormatHandler(Encoding? encoding = null) : TextFormatHandler("<!-- ", " -->", encoding)
{
    //See: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_format.ps1xml?view=powershell-7.5

    // Smallest formatting file:
    // <Configuration><ViewDefinitions><View><Name>A</Name><ViewSelectedBy><TypeName>B</TypeName></ViewSelectedBy></View></ViewDefinitions></Configuration>

    // Smallest types file:
    // <Types><Type><Name>A</Name><Members><AliasProperty><Name>B</Name><ReferencedMemberName>C</ReferencedMemberName></AliasProperty></Members></Type></Types>

    public override int MinValidSize => 148;
    public override string[] ValidExt => ["ps1xml"];
    public override bool IsValidHeader(ReadOnlySpan<byte> data) => ContainsAdv(data, "Configuration", "Types");
}