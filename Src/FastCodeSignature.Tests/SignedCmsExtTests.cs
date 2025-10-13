using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Genbox.FastCodeSignature.Extensions;
using Genbox.FastCodeSignature.Handlers;
using Genbox.FastCodeSignature.Internal;
using Genbox.FastCodeSignature.Tests.Code;

namespace Genbox.FastCodeSignature.Tests;

public class SignedCmsExtTests
{
    [Fact]
    private async Task GetCounterSignatures()
    {
        X509Certificate2 cert = X509CertificateLoader.LoadPkcs12FromFile(Path.GetFullPath(Path.Combine(Constants.FilesDir, "FastCodeSignature.pfx")), "password");
        PeFormatHandler handler = new PeFormatHandler();
        string path = Path.Combine(Constants.FilesDir, "Unsigned/WinPe/exe_unsigned.dat");

        byte[] bytes = await File.ReadAllBytesAsync(path, TestContext.Current.CancellationToken);

        CodeSignProvider provider = CodeSignProviderFactory.CreateProvider(new MemoryAllocation(bytes), handler, null);
        Signature sig = provider.CreateSignature(cert);
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