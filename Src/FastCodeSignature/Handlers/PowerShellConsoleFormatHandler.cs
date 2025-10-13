using System.Text;

namespace Genbox.FastCodeSignature.Handlers;

public sealed class PowerShellConsoleFormatHandler() : TextFormatHandler( "<!-- ", " -->", Encoding.UTF8, "psc1");