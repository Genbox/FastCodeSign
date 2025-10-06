using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using Genbox.FastCodeSignature.Abstracts;

namespace Genbox.FastCodeSignature;

public class CodeSignProvider
{
    private readonly IAllocation _allocation;
    private readonly IFormatHandler _handler;

    internal CodeSignProvider(IFormatHandler handler, IAllocation allocation)
    {
        _handler = handler;
        _allocation = allocation;
    }

    public bool HasSignature()
    {
        ReadOnlySpan<byte> data = _allocation.GetSpan();
        IContext context = _handler.GetContext(data);
        return context.IsSigned;
    }

    public SignedCms? GetSignature()
    {
        ReadOnlySpan<byte> data = _allocation.GetSpan();
        IContext context = _handler.GetContext(data);

        if (!context.IsSigned)
            return null;

        ReadOnlySpan<byte> signatureBytes = _handler.ExtractSignature(context, data);
        Debug.Assert(!signatureBytes.IsEmpty);

        SignedCms signedCms = new SignedCms();
        signedCms.Decode(signatureBytes);
        return signedCms;
    }

    public bool HasValidSignature(SignedCms signedCms)
    {
        Span<byte> span = _allocation.GetSpan();

        if (!_handler.ExtractHashFromSignedCms(signedCms, out byte[]? expectedDigest, out HashAlgorithmName hashAlgorithm))
            throw new InvalidOperationException("The CMS does not contain a valid hash.");

        IContext context = _handler.GetContext(span);

        if (!context.IsSigned)
            throw new InvalidOperationException("The file is not signed.");

        byte[] actualDigest = _handler.ComputeHash(context, span, hashAlgorithm);
        return expectedDigest.SequenceEqual(actualDigest);
    }

    public byte[] ComputeHash(HashAlgorithmName? hashAlgorithm = null)
    {
        Span<byte> data = _allocation.GetSpan();
        IContext context = _handler.GetContext(data);
        return _handler.ComputeHash(context, data, hashAlgorithm ?? HashAlgorithmName.SHA256);
    }

    public bool TryRemoveSignature(bool truncate)
    {
        Span<byte> data = _allocation.GetSpan();
        IContext context = _handler.GetContext(data);

        if (!context.IsSigned)
            return false;

        long delta = _handler.RemoveSignature(context, data);

        if (truncate)
            _allocation.SetLength((uint)(data.Length - delta));

        return true;
    }

    public Signature CreateSignature(HashAlgorithmName? hashAlgorithm = null)
    {
        hashAlgorithm ??= HashAlgorithmName.SHA256;

        Span<byte> data = _allocation.GetSpan();
        IContext context = _handler.GetContext(data);

        if (context.IsSigned)
            throw new InvalidOperationException("The file already contains a signature.");

        return _handler.CreateSignature(context, data, hashAlgorithm.Value);
    }

    public void WriteSignature(Signature signature)
    {
        Span<byte> data = _allocation.GetSpan();
        IContext context = _handler.GetContext(data);

        if (context.IsSigned)
            throw new InvalidOperationException("The file already contains a signature.");

        _handler.WriteSignature(context, _allocation, signature);
    }
}