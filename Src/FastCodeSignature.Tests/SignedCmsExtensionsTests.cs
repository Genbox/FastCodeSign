using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using Genbox.FastCodeSignature.Extensions;
using Genbox.FastCodeSignature.Handlers;
using Genbox.FastCodeSignature.Models;
using Genbox.FastCodeSignature.Tests.Code;

namespace Genbox.FastCodeSignature.Tests;

public class SignedCmsExtensionsTests
{
    [Fact]
    private void GetCounterSignaturesTest()
    {
        string path = Path.Combine(Constants.FilesDir, "Misc/ps1_countersigned.dat");

        CodeSignProvider provider = CodeSignProvider.FromFile(path, new PowerShellScriptFormatHandler(), true);
        SignedCms? cms = provider.GetSignature();
        Assert.NotNull(cms);

        Assert.Single(cms.GetCounterSignatures());
    }

    [Fact]
    private async Task CounterSignAsyncTest()
    {
        //We copy the file, as other tests use the same file, and the MMF do not like sharing
        string src = Path.Combine(Constants.FilesDir, "Signed/PowerShell/ps1_signed.dat");
        string dst = Path.Combine(Path.GetTempPath(), "ps1_signed.ps1");
        File.Copy(src, dst, true);

        CodeSignProvider provider = CodeSignProvider.FromFile(dst, new PowerShellScriptFormatHandler());
        SignedCms? cms = provider.GetSignature();
        Assert.NotNull(cms);

        Assert.Empty(cms.SignerInfos[0].UnsignedAttributes);
        await cms.SignerInfos[0].CounterSignAsync("http://timestamp.digicert.com", HashAlgorithmName.SHA256);
        Assert.Single(cms.SignerInfos[0].UnsignedAttributes);

        CounterSignature counterSig = Assert.Single(cms.SignerInfos[0].GetCounterSignatures());
        Assert.NotEqual(counterSig.TimeStamp, default);
        Assert.NotNull(counterSig.Certificate);
        Assert.NotEqual(counterSig.HashAlgorithm, default);
    }
}