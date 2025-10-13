using System.Text;

namespace Genbox.FastCodeSignature.Handlers;

public sealed class PowerShellCmdletDefinitionXmlFormatHandler() : TextFormatHandler("<!-- ", " -->", Encoding.UTF8, "cdxml");