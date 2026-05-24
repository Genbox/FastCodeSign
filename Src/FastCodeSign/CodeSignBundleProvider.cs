using Genbox.FastCodeSign.Abstracts;
using Genbox.FastCodeSign.Enums;
using Genbox.FastCodeSign.Models;

namespace Genbox.FastCodeSign;

public class CodeSignBundleProvider
{
    private readonly IBundleHandler _handler;
    private readonly string _path;

    internal CodeSignBundleProvider(IBundleHandler handler, string path)
    {
        _handler = handler;
        _path = path;
    }

    public BundleSignature CreateSignature(SignOptions options)
    {
        IContext context = _handler.GetContext(_path);

        if (context.IsSigned)
            throw new InvalidOperationException("The bundle is already signed.");

        return _handler.CreateSignature(context, options);
    }

    public void WriteSignature(BundleSignature signature)
    {
        IContext context = _handler.GetContext(_path);

        if (context.IsSigned)
            throw new InvalidOperationException("The bundle already contains a signature.");

        _handler.WriteSignature(context, signature);
    }

    public SignatureComponent RemoveSignature()
    {
        IContext context = _handler.GetContext(_path);

        if (!context.IsSigned)
            return SignatureComponent.None;

        return _handler.RemoveSignature(context);
    }

    public bool HasValidSignature()
    {
        IContext context = _handler.GetContext(_path);

        if (!context.IsSigned)
            return false;

        return _handler.HasValidSignature(context);
    }
}