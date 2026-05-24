namespace Genbox.FastCodeSign.Models;

public sealed class BundleSignature
{
    internal BundleSignature(Signature[] signatures, object? bundleInfo)
    {
        Signatures = signatures;
        BundleInfo = bundleInfo;
    }

    public Signature[] Signatures { get; }
    internal object? BundleInfo { get; }
}