using Genbox.FastCodeSign.Tests.Code;

namespace Genbox.FastCodeSign.Tests;

public class CodeSignTests
{
    private readonly string _srcFile = Path.Combine(Constants.FilesDir, "Unsigned/MachO/macho_unsigned.dat");

    [Fact]
    private void SignFileTest()
    {
        string dstFile = Path.Combine(Path.GetTempPath(), "macho_unsigned");
        File.Copy(_srcFile, dstFile, true);

        CodeSign.SignFile(dstFile, Constants.GetCert());
    }

    [Fact]
    private void SignDataTest()
    {
        CodeSign.SignData(File.ReadAllBytes(_srcFile), Constants.GetCert(), null, "macho_unsigned");
    }
}