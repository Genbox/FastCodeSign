using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Genbox.FastCodeSignature.Handlers;

public sealed class PowerShellManifestFormatHandler(X509Certificate2 cert, bool powerShell7) : TextFormatHandler(cert, "# ", "", powerShell7 ? Encoding.UTF8 : Encoding.Unicode, "psd1");