using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Genbox.FastCodeSign.Models;

namespace Genbox.FastCodeSign;

public static class CodeSign
{
    public static void SignFile(string filePath, X509Certificate2 cert, AsymmetricAlgorithm? privateKey = null, bool skipExtCheck = false)
    {
        using CodeSignFileProvider provider = CodeSignProvider.FromFile(filePath, skipExtCheck: skipExtCheck);
        Signature signature = provider.CreateSignature(cert, privateKey);
        provider.WriteSignature(signature);
    }

    public static Span<byte> SignData(byte[] data, X509Certificate2 cert, AsymmetricAlgorithm? privateKey = null, string? fileName = null, bool skipExtCheck = false)
    {
        CodeSignProvider provider = CodeSignProvider.FromData(data, fileName: fileName, skipExtCheck: skipExtCheck);
        Signature signature = provider.CreateSignature(cert, privateKey);
        provider.WriteSignature(signature);
        return provider.Allocation.GetSpan();
    }
}