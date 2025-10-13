using System.Text;

namespace Genbox.FastCodeSignature.Handlers;

public sealed class PowerShellXmlFormatHandler() : TextFormatHandler("<!-- ", " -->", Encoding.UTF8, "ps1xml");