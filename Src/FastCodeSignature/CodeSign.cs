using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Genbox.FastCodeSignature.Abstracts;
using Genbox.FastCodeSignature.Internal;

namespace Genbox.FastCodeSignature;

public static class CodeSign
{
    public static void SignFile(string filePath, X509Certificate2 cert, AsymmetricAlgorithm? privateKey, bool skipExtCheck = false)
    {
        using FileAllocation allocation = new FileAllocation(filePath);

        if (!FormatHandlerFactory.TryCreateFormatHandler(allocation, out IFormatHandler? handler, skipExtCheck ? null : filePath))
            throw new InvalidOperationException("Unable to determine the correct format handler for the file");

        CodeSignProvider provider = CodeSignProviderFactory.CreateProvider(allocation, handler);
        Signature signature = provider.CreateSignature(cert, privateKey);
        provider.WriteSignature(signature);
    }
}