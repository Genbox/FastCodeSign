using System.Text;

namespace Genbox.FastCodeSignature.Handlers;

public sealed class PowerShellModuleFormatHandler(Encoding? fallbackEncoding = null) : TextFormatHandler("# ", "", fallbackEncoding, "psm1");