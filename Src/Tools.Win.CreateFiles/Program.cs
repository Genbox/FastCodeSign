using System.Security.Cryptography.X509Certificates;
using Genbox.Tools.Win.CreateFiles.Generators;

namespace Genbox.Tools.Win.CreateFiles;

internal static class Program
{
    private static void Main()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("This tool only runs on Windows");

        X509Certificate2 cert = X509CertificateLoader.LoadPkcs12FromFile("FastCodeSign.pfx", "password");

        PowerShell.Generate(cert);
        PowerShellVectors.Generate(cert);
        WinPe.Generate(cert);
    }
}