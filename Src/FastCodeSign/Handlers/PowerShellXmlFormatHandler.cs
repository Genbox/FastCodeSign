using System.Text;

namespace Genbox.FastCodeSign.Handlers;

public sealed class PowerShellXmlFormatHandler() : TextFormatHandler("<!-- ", " -->", Encoding.UTF8)
{
    public override int MinValidSize => 0;
    public override string[] ValidExt => ["ps1xml"];
    public override bool IsValidHeader(ReadOnlySpan<byte> data) => true;
}