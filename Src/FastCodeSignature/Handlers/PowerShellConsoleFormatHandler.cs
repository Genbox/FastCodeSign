using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Genbox.FastCodeSignature.Handlers;

public sealed class PowerShellConsoleFormatHandler(X509Certificate2 cert, AsymmetricAlgorithm? privateKey, bool silent = true) : TextFormatHandler(cert, privateKey, "<!-- ", " -->", Encoding.UTF8, "psc1", silent);