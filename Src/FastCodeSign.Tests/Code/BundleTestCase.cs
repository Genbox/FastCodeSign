using System.IO.Compression;
using Genbox.FastCodeSign.Abstracts;
using Genbox.FastCodeSign.Enums;

namespace Genbox.FastCodeSign.Tests.Code;

internal sealed class BundleTestCase : XUnitTest, IDisposable
{
    private readonly string _bundlePath;
    private readonly string _bundlePathZip;

    public BundleTestCase()
    {
        _bundlePathZip = string.Empty;
        _bundlePath = string.Empty;
        ProviderFactory = _ => throw new InvalidOperationException("This test case was not initialized.");
    }

    private BundleTestCase(Func<string, CodeSignBundleProvider> providerFactory, Type handlerType, string bundlePathZip, string testMethod, bool isSigned, SignatureComponent signatureComponents) : base(handlerType.Name + " " + bundlePathZip)
    {
        _bundlePathZip = bundlePathZip;

        ProviderFactory = providerFactory;
        IsSigned = isSigned;
        SignatureComponents = signatureComponents;

        string fullPath = Path.Combine(Constants.FilesDir, bundlePathZip);
        _bundlePath = Path.Combine(Path.GetTempPath(), Path.GetFileNameWithoutExtension(fullPath), testMethod);
    }

    public Func<string, CodeSignBundleProvider> ProviderFactory { get; }

    public bool IsSigned { get; }
    public SignatureComponent SignatureComponents { get; }

    public void Dispose()
    {
        if (_bundlePath.Length != 0 && Directory.Exists(_bundlePath))
            Directory.Delete(_bundlePath, true);
    }

    public string UnpackBundle()
    {
        string fullPath = Path.Combine(Constants.FilesDir, _bundlePathZip);

        // Extract the zip file
        using FileStream fs = File.OpenRead(fullPath);
        ZipFile.ExtractToDirectory(fs, _bundlePath, true);

        return _bundlePath;
    }

    public static BundleTestCase Create(IBundleHandler handler, string bundleZipPath, bool isSigned, SignatureComponent signatureComponents, string testMethod) => new BundleTestCase(x => new CodeSignBundleProvider(handler, x), handler.GetType(), bundleZipPath, testMethod, isSigned, signatureComponents);

    public override string ToString() => Path.GetFileName(_bundlePathZip);
}