using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Text;
using Genbox.FastCodeSignature.Abstracts;
using Genbox.FastCodeSignature.Allocations;
using Genbox.FastCodeSignature.Handlers;
using Genbox.FastCodeSignature.Internal.MachObject;
using Genbox.FastCodeSignature.Models;
using Genbox.FastCodeSignature.Tests.Code;
using JetBrains.Annotations;
using Xunit.Sdk;
using static System.Buffers.Binary.BinaryPrimitives;

namespace Genbox.FastCodeSignature.Tests;

public class CodeSignProviderTests
{
    [Theory, MemberData(nameof(GetFiles))]
    private void HasSignature(TestCase tc)
    {
        CodeSignProvider provider = tc.Factory(new MemoryAllocation(File.ReadAllBytes(tc.SignedFile)));
        Assert.True(provider.HasSignature());

        CodeSignProvider provider2 = tc.Factory(new MemoryAllocation(File.ReadAllBytes(tc.UnsignedFile)));
        Assert.False(provider2.HasSignature());
    }

    [Theory, MemberData(nameof(GetFiles))]
    private async Task GetSignature(TestCase tc)
    {
        CodeSignProvider provider = tc.Factory(new MemoryAllocation(await File.ReadAllBytesAsync(tc.SignedFile, TestContext.Current.CancellationToken)));
        SignedCms? info = provider.GetSignature();
        Assert.NotNull(info);

        await Verify(info)
              .UseFileName($"{nameof(GetSignature)}-{Path.GetFileName(tc.SignedFile)}")
              .UseDirectory("Verify")
              .DisableDiff()
              .IgnoreMember("RawData");
    }

    [Theory, MemberData(nameof(GetFiles))]
    private void GetSignature_UnsignedFileShouldReturnNull(TestCase tc)
    {
        CodeSignProvider provider = tc.Factory(new MemoryAllocation(File.ReadAllBytes(tc.UnsignedFile)));
        Assert.Null(provider.GetSignature());
    }

    [Theory, MemberData(nameof(GetTestVectors))]
    private void GetSignature_PowerShellTestVectors(TestCase tc)
    {
        CodeSignProvider provider = tc.Factory(new MemoryAllocation(File.ReadAllBytes(tc.SignedFile)));

        //Normal files should all pass. They are valid files (different encoding, newlines, etc.) with signatures produced by Windows.
        if (tc.SignedFile.Contains("_normal_", StringComparison.Ordinal))
        {
            SignedCms? signedCms = provider.GetSignature();
            Assert.NotNull(signedCms);
            Assert.True(provider.HasValidSignature(signedCms)); //Verify the signature
        }
        else if (tc.SignedFile.Contains("_invalid-format_", StringComparison.Ordinal))
        {
            Assert.Throws<InvalidDataException>(() =>
            {
                SignedCms? res = provider.GetSignature();
                return res ?? throw new InvalidDataException("Null");
            });
        }
        else if (tc.SignedFile.Contains("_invalid-signature_", StringComparison.Ordinal))
        {
            SignedCms? signedCms = provider.GetSignature();
            Assert.NotNull(signedCms); //We should have been able to extract the signature

            //But the verification should fail
            Assert.False(provider.HasValidSignature(signedCms));
        }
        else if (tc.SignedFile.Contains("_invalid-base64_", StringComparison.Ordinal))
        {
            Assert.Throws<CryptographicException>(() => provider.GetSignature());
        }
        else
        {
            Assert.Fail($"There was a test vector type that was not handled: {tc.SignedFile}");
        }
    }

    [Theory, MemberData(nameof(GetFiles))]
    private void HasValidSignature(TestCase tc)
    {
        byte[] signed = File.ReadAllBytes(tc.SignedFile);
        CodeSignProvider provider = tc.Factory(new MemoryAllocation(signed));

        SignedCms? sig = provider.GetSignature();
        Assert.NotNull(sig);

        Assert.True(provider.HasValidSignature(sig));

        //Modify the file to break the signature
        signed[10] = 255;

        Assert.False(provider.HasValidSignature(sig));
    }

    [Theory, MemberData(nameof(GetFiles))]
    private void TryRemoveSignature(TestCase tc)
    {
        MemoryAllocation allocation = new MemoryAllocation(File.ReadAllBytes(tc.SignedFile));
        CodeSignProvider provider = tc.Factory(allocation);

        //Check that we have a signature - otherwise the test will be incorrect
        Assert.NotNull(provider.GetSignature());

        //Remove the signature
        Assert.True(provider.TryRemoveSignature(true));

        byte[] unsigned = File.ReadAllBytes(tc.UnsignedFile);

        Span<byte> modified = allocation.GetSpan();

        if (tc.EqualityPatch != null)
        {
            tc.EqualityPatch(modified);
            tc.EqualityPatch(unsigned);
        }

        //Make sure we don't have a signature
        //Only compare from start up to the unsigned size since Mach Objects have padding we don't remove
        Assert.Equal(modified[..unsigned.Length], unsigned.AsSpan());
    }

    [Theory, MemberData(nameof(GetFiles))]
    private void TryRemoveSignature_FileWithoutSignatureShouldReturnFalse(TestCase tc)
    {
        CodeSignProvider provider = tc.Factory(new MemoryAllocation(File.ReadAllBytes(tc.UnsignedFile)));
        Assert.False(provider.TryRemoveSignature(true));
    }

    [Theory, MemberData(nameof(GetFiles))]
    private void ComputeHash(TestCase tc)
    {
        //MachObject does not support stable hashing, so we skip it.
        if (tc.SignedFile.Contains("macho_unsigned.dat", StringComparison.Ordinal))
            return;

        CodeSignProvider provider = tc.Factory(new MemoryAllocation(File.ReadAllBytes(tc.SignedFile)));
        string hash = Convert.ToHexString(provider.ComputeHash()).ToLowerInvariant();
        Assert.Equal(tc.Hash, hash);
    }

    [Theory, MemberData(nameof(GetFiles))]
    private async Task CreateSignature(TestCase tc)
    {
        CodeSignProvider provider = tc.Factory(new MemoryAllocation(await File.ReadAllBytesAsync(tc.UnsignedFile, TestContext.Current.CancellationToken)));
        Signature sig = provider.CreateSignature(Constants.GetCert());

        await Verify(sig.SignedCms)
              .UseFileName($"{nameof(CreateSignature)}-{Path.GetFileName(tc.UnsignedFile)}")
              .UseDirectory("Verify")
              .DisableDiff()
              .IgnoreMember("RawData"); //We don't want to save these to verify files, but the SigningTime extension also makes it change
    }

    [Theory, MemberData(nameof(GetFiles))]
    private void CreateSignature_FileWithSignatureShouldThrow(TestCase tc)
    {
        CodeSignProvider provider = tc.Factory(new MemoryAllocation(File.ReadAllBytes(tc.SignedFile)));
        Assert.Throws<InvalidOperationException>(() => provider.CreateSignature(Constants.GetCert()));
    }

    [Theory, MemberData(nameof(GetFiles))]
    private async Task WriteSignature(TestCase tc)
    {
        byte[] unsigned = await File.ReadAllBytesAsync(tc.UnsignedFile, TestContext.Current.CancellationToken);
        MemoryAllocation allocation = new MemoryAllocation(unsigned);
        CodeSignProvider provider = tc.Factory(allocation);
        provider.WriteSignature(provider.CreateSignature(Constants.GetCert(), null, HashAlgorithmName.SHA256, signer =>
        {
            for (int i = signer.SignedAttributes.Count - 1; i >= 0; i--)
            {
                CryptographicAttributeObject attribute = signer.SignedAttributes[i];

                //Remove Pkcs9SigningTime to avoid differences between test runs
                if (attribute.Oid.Value == "1.2.840.113549.1.9.5")
                    signer.SignedAttributes.Remove(attribute);
            }
        }));

        await Verify(allocation.GetSpan().ToArray())
              .UseFileName($"{nameof(WriteSignature)}-{Path.GetFileName(tc.UnsignedFile)}")
              .UseDirectory("Verify")
              .DisableDiff()
              .IgnoreMember("RawData");
    }

    [Theory, MemberData(nameof(GetFiles))]
    private void WriteSignature_SignedFileShouldThrow(TestCase tc)
    {
        MemoryAllocation allocation = new MemoryAllocation(File.ReadAllBytes(tc.SignedFile));
        CodeSignProvider provider = tc.Factory(allocation);
        Assert.Throws<InvalidOperationException>(() => provider.WriteSignature(provider.CreateSignature(null!)));
    }

    [Fact]
    private void CreateProvider_FromFileAllowsUppercaseExtensions()
    {
        byte[] exe = new byte[255];
        exe[0] = (byte)'M';
        exe[1] = (byte)'Z';

        CodeSignProvider.FromData(exe, null, "UPPERCASE.EXE"); //Shouldn't throw
    }

    private static TheoryData<TestCase> GetTestVectors()
    {
        TheoryData<TestCase> data = new TheoryData<TestCase>();
        data.AddRange(Directory.GetFiles(Path.Combine(Constants.FilesDir, "TestVectors/PowerShell")).Select(x => TestCase.Create(new PowerShellScriptFormatHandler(Encoding.UTF8), Path.Combine("TestVectors/PowerShell", Path.GetFileName(x)), "unsiged-not-used", "93b3f04b6975d381ff0203406cd90489deb27da2dce44a89a3fada0b678bf0f4")));
        return data;
    }

    private static TheoryData<TestCase> GetFiles()
    {
        return
        [
            //MachO
            TestCase.Create(new MachObjectFormatHandler("macho_unsigned"), "Signed/MachO/macho_signed.dat", "Unsigned/MachO/macho_unsigned.dat", "37fcc449bdbf230e99432cf1cd2375ecf873b48c18c72a4e9123df18938244d6", PatchMachO),

            //PowerShell
            TestCase.Create(new PowerShellModuleFormatHandler(), "Signed/PowerShell/psm1_signed.dat", "Unsigned/PowerShell/psm1_unsigned.dat", "6e6c4873c7453644992df9ff4c72086d1b58a03fe7922f3095364fc4d226855e"),
            TestCase.Create(new PowerShellManifestFormatHandler(), "Signed/PowerShell/psd1_signed.dat", "Unsigned/PowerShell/psd1_unsigned.dat", "5400535fab6f06957a2901fd4d20997f232aec665103111c3561d87a36a9aa89"),
            TestCase.Create(new PowerShellConsoleFormatHandler(), "Signed/PowerShell/psc1_signed.dat", "Unsigned/PowerShell/psc1_unsigned.dat", "da4ac19e4a73ce9920f313374f8181c27f02c75200ba77fe5353428668d94796"),
            TestCase.Create(new PowerShellXmlFormatHandler(), "Signed/PowerShell/ps1xml_signed.dat", "Unsigned/PowerShell/ps1xml_unsigned.dat", "511e2b48eef835fd13fc4144835fde056c58066502f30dcc8aa99f9fc848c0c8"),
            TestCase.Create(new PowerShellScriptFormatHandler(), "Signed/PowerShell/ps1_signed.dat", "Unsigned/PowerShell/ps1_unsigned.dat", "85341b6ab21bebd52db26f414978e8a2b3ce1bb9597f21b505de486cdf493d94"),
            TestCase.Create(new PowerShellScriptFormatHandler(), "Signed/PowerShell/ps1_utf16_signed.dat", "Unsigned/PowerShell/ps1_utf16_unsigned.dat", "a7a4ef70935b667e0d4e8213a06c32f057bdaf092a559543c12eb0a14d2108d9"),
            TestCase.Create(new PowerShellCmdletDefinitionXmlFormatHandler(), "Signed/PowerShell/cdxml_signed.dat", "Unsigned/PowerShell/cdxml_unsigned.dat", "8273112b41bafcde2dcaaafc9bd092ab4d27d0af26af495ab935796f45b0ae43"),

            //WinPe
            TestCase.Create(new PeFormatHandler(), "Signed/WinPe/ax_signed.dat", "Unsigned/WinPe/ax_unsigned.dat", "deb6cb26d6c6fbdce4d0ae0245d32ddb00b248ae94a21f43194de9764766f942", PatchExe),
            TestCase.Create(new PeFormatHandler(), "Signed/WinPe/cpl_signed.dat", "Unsigned/WinPe/cpl_unsigned.dat", "53a93ff595a2b902ff210e4da7047c5adbe2fb6b8116259856daaa0ec546c4f6", PatchExe),
            TestCase.Create(new PeFormatHandler(), "Signed/WinPe/dll_signed.dat", "Unsigned/WinPe/dll_unsigned.dat", "b3f5fef5abce2b00c2eaa68a40dfaecb6731069410f4a4a2a6e67512b005aa3c", PatchExe),
            TestCase.Create(new PeFormatHandler(), "Signed/WinPe/drv_signed.dat", "Unsigned/WinPe/drv_unsigned.dat", "8732e83186dbd7a4a05c3e3f3bb8d53b32a234001c0781307794735f9e080073", PatchExe),
            TestCase.Create(new PeFormatHandler(), "Signed/WinPe/efi_signed.dat", "Unsigned/WinPe/efi_unsigned.dat", "300f3be399be71b8de2d7f5749413c2cec38dd4eecc8849d08aaf7d4f78f1799", PatchExe),
            TestCase.Create(new PeFormatHandler(), "Signed/WinPe/exe_signed.dat", "Unsigned/WinPe/exe_unsigned.dat", "0fd6baa83538304cb6de2d149015acc0da268c8d0cc285176aa6382329ec1aa0", PatchExe),
            TestCase.Create(new PeFormatHandler(), "Signed/WinPe/mui_signed.dat", "Unsigned/WinPe/mui_unsigned.dat", "3e5d6e235d1199ad2d63551837a8827678476609abf843718247dd40bdb37c24", PatchExe),
            TestCase.Create(new PeFormatHandler(), "Signed/WinPe/mun_signed.dat", "Unsigned/WinPe/mun_unsigned.dat", "424c0c0a2ac2982f885b849d79f654608483bd151f26b0a261043ecff1c9d934", PatchExe),
            TestCase.Create(new PeFormatHandler(), "Signed/WinPe/ocx_signed.dat", "Unsigned/WinPe/ocx_unsigned.dat", "c4b65e114e14a873aaeaa9e0dc4c26965270d44314d49106ff24f82c531b0292", PatchExe),
            TestCase.Create(new PeFormatHandler(), "Signed/WinPe/scr_signed.dat", "Unsigned/WinPe/scr_unsigned.dat", "8d72965b9ece78aabbca4c744b0ab69e37b01fd7546502008c74b04e3a8d023f", PatchExe),
            TestCase.Create(new PeFormatHandler(), "Signed/WinPe/sys_signed.dat", "Unsigned/WinPe/sys_unsigned.dat", "3177faa0d1f62fc48e9cb042ebc40924cf782525cc43a8ecb0ab2b6f3924f685", PatchExe),
            TestCase.Create(new PeFormatHandler(), "Signed/WinPe/winmd_signed.dat", "Unsigned/WinPe/winmd_unsigned.dat", "ae3bd70c2b98c68565673e880eff653fdf30a8dc6c24d2b27eb0bbf936227f97", PatchExe),
        ];
    }

    private static void PatchExe(Span<byte> data)
    {
        // 1) Read e_lfanew (offset to PE header) from DOS header at 0x3C
        int peHeaderOffset = ReadInt32LittleEndian(data.Slice(0x3C, 4));

        // 2) Compute Optional Header start
        int optionalHeaderStart = peHeaderOffset + 4 + 20;

        // 3) Checksum is at +0x40 from start of Optional Header (PE32 and PE32+)
        int checksumOffset = optionalHeaderStart + 0x40;

        // 4) Zero out CheckSum (uint32, little-endian)
        WriteUInt32LittleEndian(data.Slice(checksumOffset, 4), 0);
    }

    private static void PatchMachO(Span<byte> data)
    {
        MachOContext macho = MachOContext.Create(data);
        int segCmdOffset = macho.LinkEdit.Offset;

        if (macho.Is64Bit)
        {
            WriteUInt64LittleEndian(data[(segCmdOffset + 32)..], 0UL); // vmsize
            WriteUInt64LittleEndian(data[(segCmdOffset + 48)..], 0UL); // filesize
        }
        else
        {
            WriteUInt32LittleEndian(data[(segCmdOffset + 28)..], 0U); // vmsize
            WriteUInt32LittleEndian(data[(segCmdOffset + 36)..], 0U); // filesize
        }
    }

    private sealed class TestCase : IXunitSerializable
    {
        private string _id = "";

        [UsedImplicitly]
        public TestCase() {}

        private TestCase(Func<IAllocation, CodeSignProvider> factory, Type handlerType, string signedFile, string unsignedFile, string hash, Action<Span<byte>>? equalityPatch)
        {
            Factory = factory;
            SignedFile = signedFile;
            UnsignedFile = unsignedFile;
            Hash = hash;
            EqualityPatch = equalityPatch;

            _id = handlerType.Name + " " + SignedFile;
        }

        public Action<Span<byte>>? EqualityPatch { get; }
        public Func<IAllocation, CodeSignProvider> Factory { get; } = null!;
        public string SignedFile { get; } = null!;
        public string UnsignedFile { get; } = null!;
        public string Hash { get; } = null!;

        public static TestCase Create(IFormatHandler handler, string signed, string unsigned, string hash, Action<Span<byte>>? equalityPatch = null)
        {
            return new TestCase(x => new CodeSignProvider(handler, x), handler.GetType(), Path.Combine(Constants.FilesDir, signed), Path.Combine(Constants.FilesDir, unsigned), hash, equalityPatch);
        }

        public void Deserialize(IXunitSerializationInfo info) => _id = info.GetValue<string>(nameof(_id))!;
        public void Serialize(IXunitSerializationInfo info) => info.AddValue(nameof(_id), _id);

        public override string ToString()
        {
            string fileName = Path.GetFileName(SignedFile);
            return fileName[..fileName.LastIndexOf('_')];
        }
    }
}