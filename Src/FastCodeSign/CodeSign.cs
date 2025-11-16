using System.Security.Cryptography.X509Certificates;
using Genbox.FastCodeSign.Models;

namespace Genbox.FastCodeSign;

public static class CodeSign
{
    public static void SignFile(string filePath, X509Certificate2 cert, bool skipExtCheck = false) => SignFile(filePath, new SignOptions
    {
        Certificate = cert
    }, skipExtCheck);

    public static void SignFile(string filePath, SignOptions signOptions, bool skipExtCheck = false)
    {
        using CodeSignFileProvider provider = CodeSignProvider.FromFile(filePath, null, skipExtCheck);
        Signature signature = provider.CreateSignature(signOptions);
        provider.WriteSignature(signature);
    }

    public static Span<byte> SignData(byte[] data, X509Certificate2 cert, string? fileName = null, bool skipExtCheck = false) => SignData(data, new SignOptions
    {
        Certificate = cert
    }, fileName, skipExtCheck);

    public static Span<byte> SignData(byte[] data, SignOptions signOptions, string? fileName = null, bool skipExtCheck = false)
    {
        CodeSignProvider provider = CodeSignProvider.FromData(data, null, fileName, skipExtCheck);
        Signature signature = provider.CreateSignature(signOptions);
        provider.WriteSignature(signature);
        return provider.Allocation.GetSpan();
    }
}