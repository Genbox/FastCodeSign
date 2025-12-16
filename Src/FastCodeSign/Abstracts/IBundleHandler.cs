using Genbox.FastCodeSign.Enums;
using Genbox.FastCodeSign.Models;

namespace Genbox.FastCodeSign.Abstracts;

public interface IBundleHandler
{
    IContext GetContext(string path);

    bool IsBundlePath(string path);

    BundleSignature CreateSignature(IContext context, SignOptions signOptions, IBundleOptions? bundleOptions = null);

    void WriteSignature(IContext context, BundleSignature signature);

    SignatureComponent RemoveSignature(IContext context);

    bool HasValidSignature(IContext context);
}