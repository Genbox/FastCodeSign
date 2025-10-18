using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Genbox.FastCodeSign.Native.Authenticode;

namespace Genbox.Tools.Win.CreateFiles.Generators;

// This tool is able to create a set of test vectors used for checking the correctness of the PowerShell handler
// It also creates an unsigned and signed version of a simple powershell script.

internal static class PowerShell
{
    internal static void Generate(X509Certificate2 cert)
    {
        //The default PS1 file is UTF8 without BOM, and CRLF newlines.
        RSA rsa = cert.GetRSAPrivateKey()!;
        HashAlgorithmName hash = HashAlgorithmName.SHA256;

        foreach (string file in Directory.GetFiles("PowerShell", "*_unsigned.dat", SearchOption.TopDirectoryOnly))
        {
            SignFile(file, cert, rsa, hash);
        }
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