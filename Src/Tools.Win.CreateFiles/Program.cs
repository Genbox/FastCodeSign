using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Genbox.FastCodeSign.Native.Authenticode;

namespace Genbox.Tools.Win.CreateFiles;

// This tool creates signed executables files for Windows.

internal static class Program
{
    private static void Main()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("This tool only runs on Windows");

        X509Certificate2 cert = X509CertificateLoader.LoadPkcs12FromFile("FastCodeSign.pfx", "password");

        RSA rsa = cert.GetRSAPrivateKey()!;

        foreach (string file in Directory.GetFiles("WinPe", "*_unsigned.dat", SearchOption.TopDirectoryOnly))
        {
            SignFile(file, cert, rsa, HashAlgorithmName.SHA256);
        }

        // foreach (string file in Directory.GetFiles("WMI", "*_unsigned.dat", SearchOption.TopDirectoryOnly))
        // {
        //     SignFile(file, cert, rsa, HashAlgorithmName.SHA256);
        // }

        // Not working due to "Signing failed with code Unexpected cryptographic message encoding"
        // foreach (string file in Directory.GetFiles("WSH", "*_unsigned.dat", SearchOption.TopDirectoryOnly))
        // {
        //     SignFile(file, cert, rsa, HashAlgorithmName.SHA1);
        // }
    }

    private static void SignFile(string unsigned, X509Certificate2 cert, RSA rsa, HashAlgorithmName hash, TimeStampConfiguration? timeConfig = null)
    {
        Console.WriteLine($"Signing {unsigned}");

        //Get the extension (needed by authenticode to determine SIP provider)
        string name = Path.GetFileName(unsigned);
        string ext = name[..name.IndexOf('_', StringComparison.Ordinal)];

        string signed = $"{unsigned.Replace("unsigned", "signed", StringComparison.Ordinal)}.{ext}";
        File.Copy(unsigned, signed, true);
        AuthenticodeSigner.SignFile(signed, cert, rsa, hash, timeConfig);

        //Rename the file back to .dat now that it is signed
        string newName = signed[..signed.LastIndexOf('.')];
        File.Move(signed, newName, true);
    }
}