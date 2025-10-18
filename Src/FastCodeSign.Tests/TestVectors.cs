using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Text;
using Genbox.FastCodeSign.Allocations;
using Genbox.FastCodeSign.Handlers;
using Genbox.FastCodeSign.Tests.Code;

namespace Genbox.FastCodeSign.Tests;

public class TestVectors
{
    [Theory, MemberData(nameof(GetPowerShellTestVectors))]
    private void PowerShellTestVectors(TestCase tc)
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

    private static TheoryData<TestCase> GetPowerShellTestVectors()
    {
        TheoryData<TestCase> data = new TheoryData<TestCase>();
        data.AddRange(Directory.GetFiles(Path.Combine(Constants.FilesDir, "TestVectors/PowerShell")).Select(x => TestCase.Create(new PowerShellScriptFormatHandler(Encoding.UTF8), Path.Combine("TestVectors/PowerShell", Path.GetFileName(x)), "unsiged-not-used", "93b3f04b6975d381ff0203406cd90489deb27da2dce44a89a3fada0b678bf0f4")));
        return data;
    }
}