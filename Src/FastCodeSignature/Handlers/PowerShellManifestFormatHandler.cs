using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Genbox.FastCodeSignature.Handlers;

public sealed class PowerShellManifestFormatHandler(X509Certificate2 cert, AsymmetricAlgorithm? privateKey, bool powerShell7) : TextFormatHandler(cert, privateKey, "# ", "", powerShell7 ? Encoding.UTF8 : Encoding.Unicode, "psd1");