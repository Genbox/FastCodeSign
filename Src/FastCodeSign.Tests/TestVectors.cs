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

        string filename = Path.GetFileName(tc.SignedFile);

        //Normal files should all pass. They are valid files (different encoding, newlines, etc.) with signatures produced by Windows.
        if (filename.StartsWith("normal_", StringComparison.Ordinal))
        {
            SignedCms? signedCms = provider.GetSignature();
            Assert.NotNull(signedCms);
            Assert.True(provider.HasValidSignature(signedCms)); //Verify the signature
        }
        else if (filename.StartsWith("invalid-format_", StringComparison.Ordinal))
        {
            Assert.Throws<InvalidDataException>(() =>
            {
                SignedCms? res = provider.GetSignature();
                return res ?? throw new InvalidDataException("Null");
            });
        }
        else if (filename.StartsWith("invalid-signature_", StringComparison.Ordinal))
        {
            SignedCms? signedCms = provider.GetSignature();
            Assert.NotNull(signedCms); //We should have been able to extract the signature

            //But the verification should fail
            Assert.False(provider.HasValidSignature(signedCms));
        }
        else if (filename.StartsWith("invalid-base64_", StringComparison.Ordinal))
        {
            Assert.Throws<CryptographicException>(() => provider.GetSignature());
        }
        else
        {
            Assert.Fail($"There was a test vector type that was not handled: {filename}");
        }
    }

    private static TheoryData<TestCase> GetPowerShellTestVectors()
    {
        TheoryData<TestCase> data = new TheoryData<TestCase>();
        string[] files = Directory.GetFiles(Path.Combine(Constants.FilesDir, "TestVectors/PowerShell"));

        foreach (string file in files)
        {
            Encoding enc = file.Contains("utf16") ? Encoding.Unicode : Encoding.UTF8;

            data.Add(TestCase.Create(new PowerShellScriptFormatHandler(enc), Path.Combine("TestVectors/PowerShell", Path.GetFileName(file)), "", ""));
        }

        return data;
    }
}