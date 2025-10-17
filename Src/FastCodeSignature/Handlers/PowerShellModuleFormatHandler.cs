using System.Text;

namespace Genbox.FastCodeSignature.Handlers;

public sealed class PowerShellModuleFormatHandler(Encoding? fallbackEncoding = null) : TextFormatHandler("# ", "", fallbackEncoding)
{
    public override int MinValidSize => 0;
    public override string[] ValidExt => ["psm1"];
    public override bool IsValidHeader(ReadOnlySpan<byte> data) => true;
}