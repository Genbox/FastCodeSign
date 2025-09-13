using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Genbox.FastCodeSignature.Handlers;

public sealed class VisualBasicFormatHandler(X509Certificate2 cert) : TextFormatHandler(cert, "' ", "", Encoding.UTF8, "vb");