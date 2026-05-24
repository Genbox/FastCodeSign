using System.IO.Compression;
using Genbox.FastCodeSign.Abstracts;

namespace Genbox.FastCodeSign.Tests.Code;

internal sealed class BundleTestCase : XUnitTest, IDisposable
{
    private readonly string _bundlePathZip;
    private readonly string _bundlePath;

    public BundleTestCase()
    {
        _bundlePathZip = string.Empty;
        _bundlePath = string.Empty;
        ProviderFactory = _ => throw new InvalidOperationException("This test case was not initialized.");
    }

    private BundleTestCase(Func<string, CodeSignBundleProvider> providerFactory, Type handlerType, string bundlePathZip, string testMethod, bool isSigned) : base(handlerType.Name + " " + bundlePathZip)
    {
        _bundlePathZip = bundlePathZip;

        ProviderFactory = providerFactory;
        IsSigned = isSigned;

        string fullPath = Path.Combine(Constants.FilesDir, bundlePathZip);
        _bundlePath = Path.Combine(Path.GetTempPath(), Path.GetFileNameWithoutExtension(fullPath), testMethod);
    }

    public Func<string, CodeSignBundleProvider> ProviderFactory { get; }

    public string UnpackBundle()
    {
        string fullPath = Path.Combine(Constants.FilesDir, _bundlePathZip);

        // Extract the zip file
        using FileStream fs = File.OpenRead(fullPath);
        ZipFile.ExtractToDirectory(fs, _bundlePath, true);

        return _bundlePath;
    }

    public bool IsSigned { get; }

    public static BundleTestCase Create(IBundleHandler handler, string bundleZipPath, bool isSigned, string testMethod)
    {
        return new BundleTestCase(x => new CodeSignBundleProvider(handler, x), handler.GetType(), bundleZipPath, testMethod, isSigned);
    }

    public override string ToString() => Path.GetFileName(_bundlePathZip);

    public void Dispose()
    {
        if (_bundlePath.Length != 0 && Directory.Exists(_bundlePath))
            Directory.Delete(_bundlePath, true);
    }
}