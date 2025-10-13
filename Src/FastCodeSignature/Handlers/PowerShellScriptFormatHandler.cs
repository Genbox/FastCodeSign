using System.Text;

namespace Genbox.FastCodeSignature.Handlers;

public sealed class PowerShellScriptFormatHandler(Encoding? fallbackEncoding = null) : TextFormatHandler("# ", "", fallbackEncoding, "ps1");