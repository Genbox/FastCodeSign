using System.Text;

namespace Genbox.FastCodeSign.Handlers;

public sealed class PowerShellManifestFormatHandler(Encoding? fallbackEncoding = null) : TextFormatHandler("# ", "", fallbackEncoding)
{
    public override int MinValidSize => 0;
    public override string[] ValidExt => ["psd1"];
    public override bool IsValidHeader(ReadOnlySpan<byte> data) => true;
}