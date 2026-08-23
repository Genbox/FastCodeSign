using System.Security.Cryptography.X509Certificates;
using Genbox.FastCodeSign.Tests.Code;

namespace Genbox.FastCodeSign.Tests;

public class CodeSignTests
{
    private readonly string _srcFile = Path.Combine(Constants.FilesDir, "Unsigned/MachO/macho_unsigned.dat");

    [Fact]
    private void SignFileTest()
    {
        string dstFile = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        File.Copy(_srcFile, dstFile, true);

        try
        {
            using X509Certificate2 certificate = Constants.GetCert();
            CodeSign.SignFile(dstFile, certificate);

            using CodeSignFileProvider provider = CodeSignProvider.FromFile(dstFile);
            var signedCms = provider.GetSignature();
            Assert.NotNull(signedCms);
            Assert.True(provider.HasValidSignature(signedCms));
        }
        finally
        {
            File.Delete(dstFile);
        }
    }

    [Fact]
    private void SignDataTest()
    {
        using X509Certificate2 certificate = Constants.GetCert();
        byte[] signed = CodeSign.SignData(File.ReadAllBytes(_srcFile), certificate, "macho_unsigned").ToArray();

        CodeSignProvider provider = CodeSignProvider.FromData(signed, fileName: "macho_unsigned");
        var signedCms = provider.GetSignature();
        Assert.NotNull(signedCms);
        Assert.True(provider.HasValidSignature(signedCms));
    }
}