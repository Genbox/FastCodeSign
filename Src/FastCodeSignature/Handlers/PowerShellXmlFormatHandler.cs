using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Genbox.FastCodeSignature.Handlers;

public sealed class PowerShellXmlFormatHandler(X509Certificate2 cert, AsymmetricAlgorithm? privateKey) : TextFormatHandler(cert, privateKey, "<!-- ", " -->", Encoding.UTF8, "ps1xml");