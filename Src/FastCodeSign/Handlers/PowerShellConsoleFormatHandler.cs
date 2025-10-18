using System.Text;

namespace Genbox.FastCodeSign.Handlers;

public sealed class PowerShellConsoleFormatHandler() : TextFormatHandler("<!-- ", " -->", Encoding.UTF8)
{
    public override int MinValidSize => 0;
    public override string[] ValidExt => ["psc1"];
    public override bool IsValidHeader(ReadOnlySpan<byte> data) => true;
}