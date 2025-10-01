using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Genbox.FastCodeSignature.Abstracts;
using Genbox.FastCodeSignature.Handlers;
using Genbox.FastCodeSignature.Tests.Code;
using JetBrains.Annotations;
using Xunit.Sdk;

namespace Genbox.FastCodeSignature.Tests;

[SuppressMessage("Usage", "xUnit1016:MemberData must reference a public member")]
public class CodeSignTests
{
    [Theory, MemberData(nameof(GetSignedFiles))]
    private async Task GetSignature(TestCase tc)
    {
        byte[] data = await File.ReadAllBytesAsync(tc.FileName, TestContext.Current.CancellationToken);

        SignedCms? info = tc.Factory(data).GetSignature();
        Assert.NotNull(info);

        await Verify(info)
              .UseFileName($"{nameof(GetSignature)}-{Path.GetFileName(tc.FileName)}")
              .UseDirectory("Verify")
              .DisableDiff()
              .IgnoreMember("RawData");
    }

    [Theory, MemberData(nameof(GetSignedFiles))]
    private void RemoveSignature(TestCase tc)
    {
        byte[] data = File.ReadAllBytes(tc.FileName);

        using CodeSignProvider provider = tc.Factory(data);

        //Check that we have a signature
        Assert.NotNull(provider.GetSignature());

        //Remove the signature
        ReadOnlySpan<byte> modified = provider.RemoveSignature(true);
        Assert.False(modified.IsEmpty);

        //Make sure we don't have a signature
        Assert.Null(provider.GetSignature());
    }

    [Theory, MemberData(nameof(GetSignedFiles)), MemberData(nameof(GetUnsignedFiles))]
    private void ComputeHash(TestCase tc)
    {
        //MachObject does not support stable hashing, so we skip it.
        if (tc.FileName.Contains("macho_unsigned.dat", StringComparison.Ordinal))
            return;

        byte[] data = File.ReadAllBytes(tc.FileName);
        using CodeSignProvider provider = tc.Factory(data);
        byte[] hash = provider.ComputeHash();

        Assert.Equal(tc.Hash, Convert.ToHexString(hash).ToLowerInvariant());
    }

    [Theory, MemberData(nameof(GetUnsignedFiles))]
    private async Task AddSignature(TestCase tc)
    {
        byte[] data = await File.ReadAllBytesAsync(tc.FileName, TestContext.Current.CancellationToken);
        using CodeSignProvider provider1 = tc.Factory(data);

        Signature sig1 = provider1.CreateSignature(HashAlgorithmName.SHA256);
        byte[] signed = provider1.WriteSignature(sig1).ToArray();

        using CodeSignProvider provider2 = tc.Factory(signed);
        SignedCms? sig2 = provider2.GetSignature();

        Assert.NotNull(sig2);
        Assert.True(provider2.HasValidSignature(sig2), "The created signature is not valid");

        await Verify(sig2)
              .UseFileName($"{nameof(AddSignature)}-{Path.GetFileName(tc.FileName)}")
              .UseDirectory("Verify")
              .DisableDiff()
              .IgnoreMember("RawData"); //We don't want to save these to verify files, but the SigningTime extension also makes it change
    }

    [Theory, MemberData(nameof(GetUnsignedFiles))]
    private void RemoveSignature_FileWithNoSignatureShouldBeItself(TestCase tc)
    {
        byte[] data = File.ReadAllBytes(tc.FileName);
        using CodeSignProvider provider = tc.Factory(data);
        Assert.Equal(data, provider.RemoveSignature(true));
    }

    [Theory, MemberData(nameof(GetUnsignedFiles))]
    private void GetSignature_UnsignedFileShouldBeNull(TestCase tc)
    {
        byte[] data = File.ReadAllBytes(tc.FileName);
        using CodeSignProvider provider = tc.Factory(data);
        Assert.Null(provider.GetSignature());
    }

    [Theory, MemberData(nameof(GetTestVectors))]
    private void GetSignature_TestVectors(TestCase tc)
    {
        byte[] data = File.ReadAllBytes(tc.FileName);
        using CodeSignProvider provider = tc.Factory(data);

        //Normal files should all pass. They are valid files (different encoding, newlines, etc.) with signatures produced by Windows.
        if (tc.FileName.Contains("_normal_", StringComparison.Ordinal))
        {
            SignedCms? signedCms = provider.GetSignature();
            Assert.NotNull(signedCms); //We should have been able to extract the signature
            Assert.True(provider.HasValidSignature(signedCms)); //Verify the signature
        }
        else if (tc.FileName.Contains("_invalid-format_", StringComparison.Ordinal))
        {
            SignedCms? signedCms = provider.GetSignature();
            Assert.Null(signedCms); //In invalid formats, we should not be able to extract the signature
        }
        else if (tc.FileName.Contains("_invalid-signature_", StringComparison.Ordinal))
        {
            SignedCms? signedCms = provider.GetSignature();
            Assert.NotNull(signedCms); //We should have been able to extract the signature

            //But the verification should fail
            Assert.False(provider.HasValidSignature(signedCms));
        }
        else if (tc.FileName.Contains("_invalid-base64_", StringComparison.Ordinal))
        {
            Assert.Throws<CryptographicException>(() => provider.GetSignature());
        }
        else
        {
            Assert.Fail($"There was a test vector type that was not handled: {tc.FileName}");
        }
    }

    private static TheoryData<TestCase> GetTestVectors()
    {
        string p = Path.GetFullPath(Path.Combine(Constants.FilesDir, "FastCodeSignature.pfx"));
        X509Certificate2 cert = X509CertificateLoader.LoadPkcs12FromFile(p, "password");

        TheoryData<TestCase> data = new TheoryData<TestCase>();
        data.AddRange(Directory.GetFiles(Path.Combine(Constants.FilesDir, "TestVectors/PowerShell")).Select(x => TestCase.Create(new PowerShellFormatHandler(cert, true), Path.Combine("TestVectors/PowerShell", Path.GetFileName(x)), "93b3f04b6975d381ff0203406cd90489deb27da2dce44a89a3fada0b678bf0f4")));
        return data;
    }

    private static TheoryData<TestCase> GetSignedFiles()
    {
        string p = Path.GetFullPath(Path.Combine(Constants.FilesDir, "FastCodeSignature.pfx"));
        X509Certificate2 cert = X509CertificateLoader.LoadPkcs12FromFile(p, "password");

        return
        [
            //MachO
            TestCase.Create(MachObjectFormatHandler.Create(cert, cert.GetRSAPrivateKey(), "macho_signed.dat"), "Signed/MachO/macho_signed.dat", "37fcc449bdbf230e99432cf1cd2375ecf873b48c18c72a4e9123df18938244d6"),

            //PowerShell
            TestCase.Create(new PowerShellModuleFormatHandler(cert, true), "Signed/PowerShell/psm1_signed.dat", "6e6c4873c7453644992df9ff4c72086d1b58a03fe7922f3095364fc4d226855e"),
            TestCase.Create(new PowerShellManifestFormatHandler(cert, true), "Signed/PowerShell/psd1_signed.dat", "5400535fab6f06957a2901fd4d20997f232aec665103111c3561d87a36a9aa89"),
            TestCase.Create(new PowerShellConsoleFormatHandler(cert), "Signed/PowerShell/psc1_signed.dat", "da4ac19e4a73ce9920f313374f8181c27f02c75200ba77fe5353428668d94796"),
            TestCase.Create(new PowerShellXmlFormatHandler(cert), "Signed/PowerShell/ps1xml_signed.dat", "511e2b48eef835fd13fc4144835fde056c58066502f30dcc8aa99f9fc848c0c8"),
            TestCase.Create(new PowerShellFormatHandler(cert, true), "Signed/PowerShell/ps1_signed.dat", "85341b6ab21bebd52db26f414978e8a2b3ce1bb9597f21b505de486cdf493d94"),
            TestCase.Create(new PowerShellCmdletDefinitionXmlFormatHandler(cert), "Signed/PowerShell/cdxml_signed.dat", "8273112b41bafcde2dcaaafc9bd092ab4d27d0af26af495ab935796f45b0ae43"),

            //WinPe
            TestCase.Create(new PeFormatHandler(cert), "Signed/WinPe/ax_signed.dat", "deb6cb26d6c6fbdce4d0ae0245d32ddb00b248ae94a21f43194de9764766f942"),
            TestCase.Create(new PeFormatHandler(cert), "Signed/WinPe/cpl_signed.dat", "53a93ff595a2b902ff210e4da7047c5adbe2fb6b8116259856daaa0ec546c4f6"),
            TestCase.Create(new PeFormatHandler(cert), "Signed/WinPe/dll_signed.dat", "b3f5fef5abce2b00c2eaa68a40dfaecb6731069410f4a4a2a6e67512b005aa3c"),
            TestCase.Create(new PeFormatHandler(cert), "Signed/WinPe/drv_signed.dat", "8732e83186dbd7a4a05c3e3f3bb8d53b32a234001c0781307794735f9e080073"),
            TestCase.Create(new PeFormatHandler(cert), "Signed/WinPe/efi_signed.dat", "300f3be399be71b8de2d7f5749413c2cec38dd4eecc8849d08aaf7d4f78f1799"),
            TestCase.Create(new PeFormatHandler(cert), "Signed/WinPe/exe_signed.dat", "0fd6baa83538304cb6de2d149015acc0da268c8d0cc285176aa6382329ec1aa0"),
            TestCase.Create(new PeFormatHandler(cert), "Signed/WinPe/mui_signed.dat", "3e5d6e235d1199ad2d63551837a8827678476609abf843718247dd40bdb37c24"),
            TestCase.Create(new PeFormatHandler(cert), "Signed/WinPe/mun_signed.dat", "424c0c0a2ac2982f885b849d79f654608483bd151f26b0a261043ecff1c9d934"),
            TestCase.Create(new PeFormatHandler(cert), "Signed/WinPe/ocx_signed.dat", "c4b65e114e14a873aaeaa9e0dc4c26965270d44314d49106ff24f82c531b0292"),
            TestCase.Create(new PeFormatHandler(cert), "Signed/WinPe/scr_signed.dat", "8d72965b9ece78aabbca4c744b0ab69e37b01fd7546502008c74b04e3a8d023f"),
            TestCase.Create(new PeFormatHandler(cert), "Signed/WinPe/sys_signed.dat", "3177faa0d1f62fc48e9cb042ebc40924cf782525cc43a8ecb0ab2b6f3924f685"),
            TestCase.Create(new PeFormatHandler(cert), "Signed/WinPe/winmd_signed.dat", "ae3bd70c2b98c68565673e880eff653fdf30a8dc6c24d2b27eb0bbf936227f97"),
        ];
    }

    private static TheoryData<TestCase> GetUnsignedFiles()
    {
        string p = Path.GetFullPath(Path.Combine(Constants.FilesDir, "FastCodeSignature.pfx"));
        X509Certificate2 cert = X509CertificateLoader.LoadPkcs12FromFile(p, "password");

        return
        [
            //MachO
            TestCase.Create(MachObjectFormatHandler.Create(cert, cert.GetRSAPrivateKey(), "macho_unsigned.dat"), "Unsigned/MachO/macho_unsigned.dat", "37fcc449bdbf230e99432cf1cd2375ecf873b48c18c72a4e9123df18938244d6"),

            //PowerShell
            TestCase.Create(new PowerShellModuleFormatHandler(cert, true), "Unsigned/PowerShell/psm1_unsigned.dat", "6e6c4873c7453644992df9ff4c72086d1b58a03fe7922f3095364fc4d226855e"),
            TestCase.Create(new PowerShellManifestFormatHandler(cert, true), "Unsigned/PowerShell/psd1_unsigned.dat", "5400535fab6f06957a2901fd4d20997f232aec665103111c3561d87a36a9aa89"),
            TestCase.Create(new PowerShellConsoleFormatHandler(cert), "Unsigned/PowerShell/psc1_unsigned.dat", "da4ac19e4a73ce9920f313374f8181c27f02c75200ba77fe5353428668d94796"),
            TestCase.Create(new PowerShellXmlFormatHandler(cert), "Unsigned/PowerShell/ps1xml_unsigned.dat", "511e2b48eef835fd13fc4144835fde056c58066502f30dcc8aa99f9fc848c0c8"),
            TestCase.Create(new PowerShellFormatHandler(cert, true), "Unsigned/PowerShell/ps1_unsigned.dat", "85341b6ab21bebd52db26f414978e8a2b3ce1bb9597f21b505de486cdf493d94"),
            TestCase.Create(new PowerShellCmdletDefinitionXmlFormatHandler(cert), "Unsigned/PowerShell/cdxml_unsigned.dat", "8273112b41bafcde2dcaaafc9bd092ab4d27d0af26af495ab935796f45b0ae43"),

            //WinPe
            TestCase.Create(new PeFormatHandler(cert), "Unsigned/WinPe/ax_unsigned.dat", "deb6cb26d6c6fbdce4d0ae0245d32ddb00b248ae94a21f43194de9764766f942"),
            TestCase.Create(new PeFormatHandler(cert), "Unsigned/WinPe/cpl_unsigned.dat", "53a93ff595a2b902ff210e4da7047c5adbe2fb6b8116259856daaa0ec546c4f6"),
            TestCase.Create(new PeFormatHandler(cert), "Unsigned/WinPe/dll_unsigned.dat", "b3f5fef5abce2b00c2eaa68a40dfaecb6731069410f4a4a2a6e67512b005aa3c"),
            TestCase.Create(new PeFormatHandler(cert), "Unsigned/WinPe/drv_unsigned.dat", "8732e83186dbd7a4a05c3e3f3bb8d53b32a234001c0781307794735f9e080073"),
            TestCase.Create(new PeFormatHandler(cert), "Unsigned/WinPe/efi_unsigned.dat", "300f3be399be71b8de2d7f5749413c2cec38dd4eecc8849d08aaf7d4f78f1799"),
            TestCase.Create(new PeFormatHandler(cert), "Unsigned/WinPe/exe_unsigned.dat", "0fd6baa83538304cb6de2d149015acc0da268c8d0cc285176aa6382329ec1aa0"),
            TestCase.Create(new PeFormatHandler(cert), "Unsigned/WinPe/mui_unsigned.dat", "3e5d6e235d1199ad2d63551837a8827678476609abf843718247dd40bdb37c24"),
            TestCase.Create(new PeFormatHandler(cert), "Unsigned/WinPe/mun_unsigned.dat", "424c0c0a2ac2982f885b849d79f654608483bd151f26b0a261043ecff1c9d934"),
            TestCase.Create(new PeFormatHandler(cert), "Unsigned/WinPe/ocx_unsigned.dat", "c4b65e114e14a873aaeaa9e0dc4c26965270d44314d49106ff24f82c531b0292"),
            TestCase.Create(new PeFormatHandler(cert), "Unsigned/WinPe/scr_unsigned.dat", "8d72965b9ece78aabbca4c744b0ab69e37b01fd7546502008c74b04e3a8d023f"),
            TestCase.Create(new PeFormatHandler(cert), "Unsigned/WinPe/sys_unsigned.dat", "3177faa0d1f62fc48e9cb042ebc40924cf782525cc43a8ecb0ab2b6f3924f685"),
            TestCase.Create(new PeFormatHandler(cert), "Unsigned/WinPe/winmd_unsigned.dat", "ae3bd70c2b98c68565673e880eff653fdf30a8dc6c24d2b27eb0bbf936227f97"),
        ];
    }

    private sealed class TestCase : IXunitSerializable
    {
        private string _id = "";

        [UsedImplicitly]
        public TestCase() {}

        private TestCase(Func<Memory<byte>, CodeSignProvider> factory, Type handlerType, string fileName, string hash)
        {
            Factory = factory;
            FileName = fileName;
            Hash = hash;

            _id = handlerType.Name + " " + FileName;
        }

        public Func<Memory<byte>, CodeSignProvider> Factory { get; } = null!;
        public string FileName { get; } = null!;
        public string Hash { get; } = null!;

        public static TestCase Create(IFormatHandler handler, string fileName, string hash)
        {
            return new TestCase(bytes => CodeSign.CreateProvider(bytes, handler), handler.GetType(), Path.Combine(Constants.FilesDir, fileName), hash);
        }

        public void Deserialize(IXunitSerializationInfo info) => _id = info.GetValue<string>(nameof(_id))!;
        public void Serialize(IXunitSerializationInfo info) => info.AddValue(nameof(_id), _id);

        public override string ToString() => Path.GetFileName(FileName);
    }
}