using System.Security.Cryptography;
using static Genbox.FastCodeSign.Native.Authenticode.Tests.Code.Constants;

namespace Genbox.FastCodeSign.Native.Authenticode.Tests;

public class AuthenticodeTests
{
    [Theory]
    [InlineData("Signed/WinPe/exe_signed.dat", WinVerifyTrustResult.SUCCESS)]
    [InlineData("Unsigned/WinPe/exe_unsigned.dat", WinVerifyTrustResult.TRUST_E_NOSIGNATURE)]
    public void VerifyFile(string fileName, WinVerifyTrustResult expected)
    {
        string path = Path.Combine(FilesDir, fileName);
        Assert.Equal(expected, Authenticode.VerifyFile(path));
    }

    [Theory]
    [InlineData("exe_signed.dat", "CN=FastCodeSignature")]
    public void VerifyFileExt(string fileName, string expectedSigner)
    {
        string path = Path.Combine(FilesDir, "Signed/WinPe/", fileName);
        Assert.Equal(WinVerifyTrustResult.SUCCESS, Authenticode.VerifyFileExt(path, out string? signer, out byte[]? certificate));

        Assert.NotNull(signer);
        Assert.NotNull(certificate);

        Assert.Equal(expectedSigner, signer);
    }

    [Theory]
    [InlineData("exe_signed.dat", "19de46d7639244c10615417b61884037ec73ccf3", "0fd6baa83538304cb6de2d149015acc0da268c8d0cc285176aa6382329ec1aa0")]
    [InlineData("dll_signed.dat", "552f527b80611c4d8447fa73df95cd2c87224704", "b3f5fef5abce2b00c2eaa68a40dfaecb6731069410f4a4a2a6e67512b005aa3c")]
    public void GetHash(string fileName, string expectedSha1, string expectedSha256)
    {
        string path = Path.Combine(FilesDir, "Signed/WinPe/", fileName);
        byte[] sha1Hash = Authenticode.GetPeHash(path, HashAlgorithmName.SHA1);
        Assert.Equal(expectedSha1, Convert.ToHexString(sha1Hash).ToLowerInvariant());

        byte[] sha256Hash = Authenticode.GetPeHash(path, HashAlgorithmName.SHA256);
        Assert.Equal(expectedSha256, Convert.ToHexString(sha256Hash).ToLowerInvariant());
    }

    [Theory]
    [InlineData(@"C:\Windows\regedit.exe", WinVerifyTrustResult.SUCCESS, "669670ca90bdb1f1d945fc6c4a42a1544fa7e5b7e6100db760ba9b3fbe044afa")]
    public void VerifyFileWithCab(string fileName, WinVerifyTrustResult expectedRes, string expectedHash)
    {
        Assert.Equal(expectedRes, Authenticode.VerifyFileWithCab(fileName, out byte[] hash));
        Assert.Equal(expectedHash, Convert.ToHexString(hash).ToLowerInvariant());
    }
}