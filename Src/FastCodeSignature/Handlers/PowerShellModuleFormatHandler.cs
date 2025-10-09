using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Genbox.FastCodeSignature.Handlers;

public sealed class PowerShellModuleFormatHandler(X509Certificate2 cert, AsymmetricAlgorithm? privateKey, Encoding? fallbackEncoding, bool silent = true) : TextFormatHandler(cert, privateKey, "# ", "", fallbackEncoding, "psm1", silent);