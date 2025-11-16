using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Text;
using Genbox.FastCodeSign.Allocations;
using Genbox.FastCodeSign.Handlers;
using Genbox.FastCodeSign.Internal.MachObject;
using Genbox.FastCodeSign.Models;
using Genbox.FastCodeSign.Tests.Code;
using static System.Buffers.Binary.BinaryPrimitives;

namespace Genbox.FastCodeSign.Tests;

public class CodeSignProviderTests
{
    [Theory, MemberData(nameof(GetTestCases))]
    private void HasSignature(TestCase tc)
    {
        CodeSignProvider provider = tc.ProviderFactory(new MemoryAllocation(File.ReadAllBytes(tc.Signed)));
        Assert.True(provider.HasSignature());

        CodeSignProvider provider2 = tc.ProviderFactory(new MemoryAllocation(File.ReadAllBytes(tc.Unsigned)));
        Assert.False(provider2.HasSignature());
    }

    [Theory, MemberData(nameof(GetTestCases))]
    private async Task GetSignature(TestCase tc)
    {
        CodeSignProvider provider = tc.ProviderFactory(new MemoryAllocation(await File.ReadAllBytesAsync(tc.Signed, TestContext.Current.CancellationToken)));
        SignedCms? info = provider.GetSignature();
        Assert.NotNull(info);

        await Verify(info)
              .UseFileName($"{nameof(GetSignature)}-{Path.GetFileName(tc.Signed)}")
              .UseDirectory("Verify/" + nameof(CodeSignProviderTests))
              .DisableDiff()
              .IgnoreMember("RawData");
    }

    [Theory, MemberData(nameof(GetTestCases))]
    private void GetSignature_UnsignedFileShouldReturnNull(TestCase tc)
    {
        CodeSignProvider provider = tc.ProviderFactory(new MemoryAllocation(File.ReadAllBytes(tc.Unsigned)));
        Assert.Null(provider.GetSignature());
    }

    [Theory, MemberData(nameof(GetTestCases))]
    private void HasValidSignature(TestCase tc)
    {
        byte[] signed = File.ReadAllBytes(tc.Signed);
        CodeSignProvider provider = tc.ProviderFactory(new MemoryAllocation(signed));

        SignedCms? sig = provider.GetSignature();
        Assert.NotNull(sig);

        Assert.True(provider.HasValidSignature(sig));

        //Modify the file to break the signature
        signed[10] = 255;

        Assert.False(provider.HasValidSignature(sig));
    }

    [Theory, MemberData(nameof(GetTestCases))]
    private void TryRemoveSignature(TestCase tc)
    {
        MemoryAllocation allocation = new MemoryAllocation(File.ReadAllBytes(tc.Signed));
        CodeSignProvider provider = tc.ProviderFactory(allocation);

        //Check that we have a signature - otherwise the test will be incorrect
        Assert.NotNull(provider.GetSignature());

        //Remove the signature
        Assert.True(provider.TryRemoveSignature(true));

        byte[] unsigned = File.ReadAllBytes(tc.Unsigned);

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

    [Theory, MemberData(nameof(GetTestCases))]
    private void TryRemoveSignature_FileWithoutSignatureShouldReturnFalse(TestCase tc)
    {
        CodeSignProvider provider = tc.ProviderFactory(new MemoryAllocation(File.ReadAllBytes(tc.Unsigned)));
        Assert.False(provider.TryRemoveSignature(true));
    }

    [Theory, MemberData(nameof(GetTestCases))]
    private void ComputeHash(TestCase tc)
    {
        //MachObject does not support stable hashing, so we skip it.
        if (tc.Signed.Contains("macho_unsigned.dat", StringComparison.Ordinal))
            return;

        CodeSignProvider provider = tc.ProviderFactory(new MemoryAllocation(File.ReadAllBytes(tc.Signed)));
        string hash = Convert.ToHexString(provider.ComputeHash()).ToLowerInvariant();
        Assert.Equal(tc.Hash, hash);
    }

    [Theory, MemberData(nameof(GetTestCases))]
    private async Task CreateSignature(TestCase tc)
    {
        CodeSignProvider provider = tc.ProviderFactory(new MemoryAllocation(await File.ReadAllBytesAsync(tc.Unsigned, TestContext.Current.CancellationToken)));
        Signature sig = provider.CreateSignature(new SignOptions { Certificate = Constants.GetCert() }, tc.FormatOptions);

        await Verify(sig.SignedCms)
              .UseFileName($"{nameof(CreateSignature)}-{Path.GetFileName(tc.Unsigned)}")
              .UseDirectory("Verify/" + nameof(CodeSignProviderTests))
              .DisableDiff()
              .IgnoreMember("RawData"); //We don't want to save these to verify files, but the SigningTime extension also makes it change
    }

    [Theory, MemberData(nameof(GetTestCases))]
    private void CreateSignature_FileWithSignatureShouldThrow(TestCase tc)
    {
        CodeSignProvider provider = tc.ProviderFactory(new MemoryAllocation(File.ReadAllBytes(tc.Signed)));
        Assert.Throws<InvalidOperationException>(() => provider.CreateSignature(new SignOptions { Certificate = Constants.GetCert() }));
    }

    [Theory, MemberData(nameof(GetTestCases))]
    private async Task WriteSignature(TestCase tc)
    {
        byte[] unsigned = await File.ReadAllBytesAsync(tc.Unsigned, TestContext.Current.CancellationToken);
        MemoryAllocation allocation = new MemoryAllocation(unsigned);
        CodeSignProvider provider = tc.ProviderFactory(allocation);
        provider.WriteSignature(provider.CreateSignature(new SignOptions { Certificate = Constants.GetCert() }, tc.FormatOptions, signer =>
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
              .UseFileName($"{nameof(WriteSignature)}-{Path.GetFileName(tc.Unsigned)}")
              .UseDirectory("Verify/" + nameof(CodeSignProviderTests))
              .DisableDiff()
              .IgnoreMember("RawData");
    }

    [Theory, MemberData(nameof(GetTestCases))]
    private void WriteSignature_SignedFileShouldThrow(TestCase tc)
    {
        MemoryAllocation allocation = new MemoryAllocation(File.ReadAllBytes(tc.Signed));
        CodeSignProvider provider = tc.ProviderFactory(allocation);
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

    private static TheoryData<TestCase> GetTestCases() =>
    [
        //MachO
        TestCase.Create(new MachObjectFormatHandler(), "Signed/MachO/macho_signed.dat", "Unsigned/MachO/macho_unsigned.dat", "37fcc449bdbf230e99432cf1cd2375ecf873b48c18c72a4e9123df18938244d6", new MachObjectFormatOptions { Identifier = "macho_unsigned" }, PatchMachO),

        //PowerShell
        TestCase.Create(new PowerShellModuleFormatHandler(Encoding.UTF8), "Signed/PowerShell/psm1_signed.dat", "Unsigned/PowerShell/psm1_unsigned.dat", "6e6c4873c7453644992df9ff4c72086d1b58a03fe7922f3095364fc4d226855e"),
        TestCase.Create(new PowerShellManifestFormatHandler(Encoding.UTF8), "Signed/PowerShell/psd1_signed.dat", "Unsigned/PowerShell/psd1_unsigned.dat", "0657a7bdf14c63131ed8675353188861a484f8a62e6e3a37d153977eaa288460"),
        TestCase.Create(new PowerShellConsoleFormatHandler(Encoding.UTF8), "Signed/PowerShell/psc1_signed.dat", "Unsigned/PowerShell/psc1_unsigned.dat", "da4ac19e4a73ce9920f313374f8181c27f02c75200ba77fe5353428668d94796"),
        TestCase.Create(new PowerShellXmlFormatHandler(Encoding.UTF8), "Signed/PowerShell/ps1xml_signed.dat", "Unsigned/PowerShell/ps1xml_unsigned.dat", "511e2b48eef835fd13fc4144835fde056c58066502f30dcc8aa99f9fc848c0c8"),
        TestCase.Create(new PowerShellScriptFormatHandler(Encoding.UTF8), "Signed/PowerShell/ps1_signed.dat", "Unsigned/PowerShell/ps1_unsigned.dat", "85341b6ab21bebd52db26f414978e8a2b3ce1bb9597f21b505de486cdf493d94"),
        TestCase.Create(new PowerShellScriptFormatHandler(Encoding.Unicode), "Signed/PowerShell/ps1_utf16_signed.dat", "Unsigned/PowerShell/ps1_utf16_unsigned.dat", "a7a4ef70935b667e0d4e8213a06c32f057bdaf092a559543c12eb0a14d2108d9"),
        TestCase.Create(new PowerShellCmdletDefinitionXmlFormatHandler(Encoding.UTF8), "Signed/PowerShell/cdxml_signed.dat", "Unsigned/PowerShell/cdxml_unsigned.dat", "84f3b186e2c0c6f180a46fb9d75f69ad3288cabc729a7bf529f9f2585f960fe5"),

        //WinPe
        TestCase.Create(new PeFormatHandler(), "Signed/WinPe/ax_signed.dat", "Unsigned/WinPe/ax_unsigned.dat", "deb6cb26d6c6fbdce4d0ae0245d32ddb00b248ae94a21f43194de9764766f942", equalityPatch: PatchExe),
        TestCase.Create(new PeFormatHandler(), "Signed/WinPe/cpl_signed.dat", "Unsigned/WinPe/cpl_unsigned.dat", "53a93ff595a2b902ff210e4da7047c5adbe2fb6b8116259856daaa0ec546c4f6", equalityPatch: PatchExe),
        TestCase.Create(new PeFormatHandler(), "Signed/WinPe/dll_signed.dat", "Unsigned/WinPe/dll_unsigned.dat", "b3f5fef5abce2b00c2eaa68a40dfaecb6731069410f4a4a2a6e67512b005aa3c", equalityPatch: PatchExe),
        TestCase.Create(new PeFormatHandler(), "Signed/WinPe/drv_signed.dat", "Unsigned/WinPe/drv_unsigned.dat", "8732e83186dbd7a4a05c3e3f3bb8d53b32a234001c0781307794735f9e080073", equalityPatch: PatchExe),
        TestCase.Create(new PeFormatHandler(), "Signed/WinPe/efi_signed.dat", "Unsigned/WinPe/efi_unsigned.dat", "300f3be399be71b8de2d7f5749413c2cec38dd4eecc8849d08aaf7d4f78f1799", equalityPatch: PatchExe),
        TestCase.Create(new PeFormatHandler(), "Signed/WinPe/exe_signed.dat", "Unsigned/WinPe/exe_unsigned.dat", "0fd6baa83538304cb6de2d149015acc0da268c8d0cc285176aa6382329ec1aa0", equalityPatch: PatchExe),
        TestCase.Create(new PeFormatHandler(), "Signed/WinPe/mui_signed.dat", "Unsigned/WinPe/mui_unsigned.dat", "3e5d6e235d1199ad2d63551837a8827678476609abf843718247dd40bdb37c24", equalityPatch: PatchExe),
        TestCase.Create(new PeFormatHandler(), "Signed/WinPe/mun_signed.dat", "Unsigned/WinPe/mun_unsigned.dat", "424c0c0a2ac2982f885b849d79f654608483bd151f26b0a261043ecff1c9d934", equalityPatch: PatchExe),
        TestCase.Create(new PeFormatHandler(), "Signed/WinPe/ocx_signed.dat", "Unsigned/WinPe/ocx_unsigned.dat", "c4b65e114e14a873aaeaa9e0dc4c26965270d44314d49106ff24f82c531b0292", equalityPatch: PatchExe),
        TestCase.Create(new PeFormatHandler(), "Signed/WinPe/scr_signed.dat", "Unsigned/WinPe/scr_unsigned.dat", "8d72965b9ece78aabbca4c744b0ab69e37b01fd7546502008c74b04e3a8d023f", equalityPatch: PatchExe),
        TestCase.Create(new PeFormatHandler(), "Signed/WinPe/sys_signed.dat", "Unsigned/WinPe/sys_unsigned.dat", "3177faa0d1f62fc48e9cb042ebc40924cf782525cc43a8ecb0ab2b6f3924f685", equalityPatch: PatchExe),
        TestCase.Create(new PeFormatHandler(), "Signed/WinPe/winmd_signed.dat", "Unsigned/WinPe/winmd_unsigned.dat", "ae3bd70c2b98c68565673e880eff653fdf30a8dc6c24d2b27eb0bbf936227f97", equalityPatch: PatchExe),
    ];

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
}