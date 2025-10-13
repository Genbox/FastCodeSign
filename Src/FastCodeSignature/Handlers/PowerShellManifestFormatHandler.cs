using System.Text;

namespace Genbox.FastCodeSignature.Handlers;

public sealed class PowerShellManifestFormatHandler(Encoding? fallbackEncoding = null) : TextFormatHandler("# ", "", fallbackEncoding, "psd1");