using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Genbox.FastCodeSign.Examples;

internal static class Program
{
    private static void Main()
    {
        byte[] pwsh = """
                      Write-Host "Hello world!"
                      """u8.ToArray();

        // You need to provide a code signing certificate
        using X509Certificate2 cert = X509CertificateLoader.LoadPkcs12FromFile("FastCodeSign.pfx", "password");

        Span<byte> signed = CodeSign.SignData(pwsh, cert, "script.ps1");
        Console.WriteLine(Encoding.UTF8.GetString(signed));
    }
}