namespace Genbox.FastCodeSign.Benchmarks;

public class GeneralBenchmarks
{
    private readonly byte[] _script = "Write-Host \"Hello world!\""u8.ToArray();

    [Benchmark]
    public byte[] ComputePowerShellHash()
    {
        CodeSignProvider provider = CodeSignProvider.FromData((byte[])_script.Clone(), fileName: "script.ps1");
        return provider.ComputeHash();
    }
}