using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Genbox.FastCodeSignature.Extensions;
using Genbox.FastCodeSignature.Handlers;
using Genbox.FastCodeSignature.Models;
using Genbox.FastCodeSignature.Tests.Code;

namespace Genbox.FastCodeSignature.Tests;

public class SignedCmsExtensionsTests
{
    [Fact]
    private async Task GetCounterSignatures()
    {
        string path = Path.Combine(Constants.FilesDir, "Unsigned/WinPe/exe_unsigned.dat");

        byte[] bytes = await File.ReadAllBytesAsync(path, TestContext.Current.CancellationToken);

        CodeSignProvider provider = CodeSignProvider.FromData(bytes, new PeFormatHandler());
        Signature sig = provider.CreateSignature(Constants.GetCert());
        SignedCms cms = sig.SignedCms;

        SignerInfo info = cms.SignerInfos[0];

        Assert.Empty(info.UnsignedAttributes);

        //Countersign the CMS
        await info.CounterSignAsync("http://timestamp.digicert.com", HashAlgorithmName.SHA256);
        info = cms.SignerInfos[0]; //Do not refactor this line. We have to re-extract the signerinfo as it seems to be replaced
        Assert.Single(info.UnsignedAttributes);

        CounterSignature counterSig = Assert.Single(info.GetCounterSignatures());
        Assert.NotEqual(counterSig.TimeStamp, default);
        Assert.NotNull(counterSig.Certificate);
        Assert.NotEqual(counterSig.HashAlgorithm, default);
    }
}