using System.Text;

namespace Genbox.FastCodeSign.Handlers;

public sealed class PowerShellCmdletDefinitionXmlFormatHandler() : TextFormatHandler("<!-- ", " -->", Encoding.UTF8)
{
    public override int MinValidSize => 0;
    public override string[] ValidExt => ["cdxml"];
    public override bool IsValidHeader(ReadOnlySpan<byte> data) => true;
}