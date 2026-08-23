using System.Text;
using Genbox.FastCodeSign.Allocations;
using Genbox.FastCodeSign.BundleHandlers;

namespace Genbox.FastCodeSign.Tests;

public class FormatAndBundleSecurityTests
{
    [Fact]
    private void PowerShellModuleWithoutFunctionIsDetected()
    {
        byte[] data = Encoding.UTF8.GetBytes(new string('#', 9000) + "\r\n$Value = 42\r\n");

        CodeSignProvider provider = CodeSignProvider.FromData(data, fileName: "module.psm1");

        Assert.NotEmpty(provider.ComputeHash());
    }

    [Fact]
    private void EmptyPowerShellModuleIsDetected()
    {
        CodeSignProvider provider = CodeSignProvider.FromData([], fileName: "module.psm1");

        Assert.NotEmpty(provider.ComputeHash());
    }

    [Fact]
    private void BomlessUtf16PowerShellIsDetected()
    {
        byte[] data = Encoding.Unicode.GetBytes("Write-Output 'UTF-16'\r\n");

        CodeSignProvider provider = CodeSignProvider.FromData(data, fileName: "script.ps1");

        Assert.NotEmpty(provider.ComputeHash());
    }

    [Fact]
    private void EmptyFileAllocationCanBeResized()
    {
        string path = Path.GetTempFileName();
        try
        {
            using FileAllocation allocation = new FileAllocation(path);
            Assert.True(allocation.GetSpan().IsEmpty);

            allocation.SetLength(4);

            Assert.Equal(4, allocation.GetSpan().Length);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    private void AppBundleRejectsExecutablePathTraversal()
    {
        string bundle = CreateBundle("../Outside");
        try
        {
            AppBundleHandler handler = new AppBundleHandler();
            Assert.Throws<InvalidDataException>(() => handler.GetContext(bundle));
        }
        finally
        {
            Directory.Delete(bundle, true);
        }
    }

    [Fact]
    private void AppBundleRejectsExternalExecutableSymlink()
    {
        string bundle = CreateBundle("App");
        string external = Path.GetTempFileName();
        try
        {
            string executable = Path.Combine(bundle, "Contents", "MacOS", "App");
            try
            {
                File.CreateSymbolicLink(executable, external);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
            {
                Assert.Skip("Symbolic links are not available in this environment.");
            }

            AppBundleHandler handler = new AppBundleHandler();
            Assert.Throws<InvalidDataException>(() => handler.GetContext(bundle));
        }
        finally
        {
            Directory.Delete(bundle, true);
            File.Delete(external);
        }
    }

    private static string CreateBundle(string executable)
    {
        string bundle = Path.Combine(Path.GetTempPath(), $"FastCodeSign-{Guid.NewGuid():N}.app");
        string contents = Path.Combine(bundle, "Contents");
        Directory.CreateDirectory(Path.Combine(contents, "MacOS"));
        File.WriteAllText(Path.Combine(contents, "Info.plist"), $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0"><dict>
            <key>CFBundleExecutable</key><string>{executable}</string>
            <key>CFBundleIdentifier</key><string>com.fastcodesign.security-test</string>
            </dict></plist>
            """);
        return bundle;
    }
}