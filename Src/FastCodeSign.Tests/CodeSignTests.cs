using System.Buffers.Binary;
using System.IO.Compression;
using Genbox.FastCodeSign.Allocations;
using Genbox.FastCodeSign.BundleHandlers;
using Genbox.FastCodeSign.Enums;
using Genbox.FastCodeSign.Handlers;
using Genbox.FastCodeSign.Helpers;
using Genbox.FastCodeSign.Internal.Bundles;
using Genbox.FastCodeSign.Internal.MachObject;
using Genbox.FastCodeSign.Internal.MachObject.Headers.Enums;
using Genbox.FastCodeSign.MachObjects;
using Genbox.FastCodeSign.Tests.Code;
using MachObjectModel = Genbox.FastCodeSign.Models.MachObject;

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
            using var certificate = Constants.GetCert();
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
        using var certificate = Constants.GetCert();
        byte[] signed = CodeSign.SignData(File.ReadAllBytes(_srcFile), certificate, "macho_unsigned").ToArray();

        CodeSignProvider provider = CodeSignProvider.FromData(signed, fileName: "macho_unsigned");
        var signedCms = provider.GetSignature();
        Assert.NotNull(signedCms);
        Assert.True(provider.HasValidSignature(signedCms));
    }

    [Fact]
    private void SignBundleTest()
    {
        string bundlePath = Path.Combine(Path.GetTempPath(), "FastCodeSign-" + Path.GetRandomFileName());

        try
        {
            ZipFile.ExtractToDirectory(Path.Combine(Constants.FilesDir, "Unsigned/AppBundle/MyApp.dat"), bundlePath);

            CodeSignBundleProvider provider = CodeSignProvider.FromBundle(bundlePath);
            Assert.False(provider.HasValidSignature());

            using var certificate = Constants.GetCert();
            CodeSign.SignBundle(bundlePath, new SignOptions { Certificate = certificate, ExistingSignatureBehavior = ExistingSignatureBehavior.Replace }, new AppBundleOptions
            {
                SigningFlags = MachObjectSigningFlags.HardenedRuntime
            });

            provider = CodeSignProvider.FromBundle(bundlePath);
            Assert.True(provider.HasValidSignature());
            Assert.True(File.Exists(Path.Combine(bundlePath, "Contents", "_CodeSignature", "CodeResources")));

            string executablePath = AppBundleContext.Create(bundlePath).BundleExecutablePath;
            using FileAllocation allocation = new FileAllocation(executablePath);
            ReadOnlySpan<byte> executable = allocation.GetSpan();
            foreach (MachObjectModel machObject in MachObjectHelper.GetMachObjects(executable))
            {
                ReadOnlySpan<byte> slice = machObject.GetSpan(executable);
                MachOContext machContext = MachOContext.Create(slice);
                Assert.True(MachObjectFormatHandler.TryExtractSpecialSlot(machContext, slice, CsSlot.CodeDirectory, out ReadOnlySpan<byte> codeDirectory));
                Assert.True(((CdFlags)BinaryPrimitives.ReadUInt32BigEndian(codeDirectory[12..])).HasFlag(CdFlags.Runtime));
            }
        }
        finally
        {
            if (Directory.Exists(bundlePath))
                Directory.Delete(bundlePath, true);
        }
    }
}