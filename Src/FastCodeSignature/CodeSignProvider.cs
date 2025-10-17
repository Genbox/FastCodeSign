using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Genbox.FastCodeSignature.Abstracts;
using Genbox.FastCodeSignature.Allocations;
using Genbox.FastCodeSignature.Internal;
using Genbox.FastCodeSignature.Internal.Helpers;
using Genbox.FastCodeSignature.Models;

namespace Genbox.FastCodeSignature;

public class CodeSignProvider
{
    private readonly IFormatHandler _handler;

    internal CodeSignProvider(IFormatHandler handler, IAllocation allocation)
    {
        _handler = handler;
        Allocation = allocation;
    }

    public IAllocation Allocation { get; }

    public static CodeSignFileProvider FromFile(string filePath, IFormatHandler? handler = null, bool skipExtCheck = false)
    {
        FileAllocation allocation = new FileAllocation(filePath); //We don't dispose this here. Instead, we let CodeSignFileProvider do it

        string fileName = Path.GetFileName(filePath);
        ReadOnlySpan<byte> span = allocation.GetSpan();

        if (handler == null)
            handler = GetHandler(span, fileName, skipExtCheck);
        else
            ValidateHandler(handler, span, fileName, skipExtCheck);

        return new CodeSignFileProvider(handler, allocation);
    }

    public static CodeSignProvider FromData(byte[] data, IFormatHandler? handler = null, string? fileName = null, bool skipExtCheck = false)
    {
        MemoryAllocation allocation = new MemoryAllocation(data);
        return FromAllocation(allocation, handler, fileName, skipExtCheck);
    }

    public static CodeSignProvider FromAllocation(IAllocation allocation, IFormatHandler? handler = null, string? fileName = null, bool skipExtCheck = false)
    {
        ReadOnlySpan<byte> span = allocation.GetSpan();

        if (handler == null)
            handler = GetHandler(span, fileName, skipExtCheck);
        else
            ValidateHandler(handler, span, fileName, skipExtCheck);

        return new CodeSignProvider(handler, allocation);
    }

    public bool HasSignature()
    {
        ReadOnlySpan<byte> data = Allocation.GetSpan();
        IContext context = _handler.GetContext(data);
        return context.IsSigned;
    }

    public SignedCms? GetSignature()
    {
        ReadOnlySpan<byte> data = Allocation.GetSpan();
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
        Span<byte> span = Allocation.GetSpan();

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
        Span<byte> data = Allocation.GetSpan();
        IContext context = _handler.GetContext(data);
        return _handler.ComputeHash(context, data, hashAlgorithm ?? HashAlgorithmName.SHA256);
    }

    public bool TryRemoveSignature(bool truncate)
    {
        Span<byte> data = Allocation.GetSpan();
        IContext context = _handler.GetContext(data);

        if (!context.IsSigned)
            return false;

        long delta = _handler.RemoveSignature(context, data);

        if (truncate)
            Allocation.SetLength((uint)(data.Length - delta));

        return true;
    }

    public Signature CreateSignature(X509Certificate2 cert, AsymmetricAlgorithm? privateKey = null, HashAlgorithmName? hashAlgorithm = null, Action<CmsSigner>? configureSigner = null, bool silent = true)
    {
        hashAlgorithm ??= HashAlgorithmName.SHA256;

        Span<byte> data = Allocation.GetSpan();
        IContext context = _handler.GetContext(data);

        if (context.IsSigned)
            throw new InvalidOperationException("The file already contains a signature.");

        return _handler.CreateSignature(context, data, cert, privateKey, hashAlgorithm.Value, configureSigner, silent);
    }

    public void WriteSignature(Signature signature)
    {
        Span<byte> data = Allocation.GetSpan();
        IContext context = _handler.GetContext(data);

        if (context.IsSigned)
            throw new InvalidOperationException("The file already contains a signature.");

        _handler.WriteSignature(context, Allocation, signature);
    }

    private static IFormatHandler GetHandler(ReadOnlySpan<byte> span, string? fileName, bool skipExtCheck)
    {
        IFormatHandler? factory = FormatHandlerFactory.Get(span, fileName, skipExtCheck);

        if (factory == null)
            throw new InvalidOperationException("Unable to find a valid handler");

        return factory;
    }

    private static void ValidateHandler(IFormatHandler handler, ReadOnlySpan<byte> span, string? fileName, bool skipExtCheck)
    {
        string? ext = fileName == null ? null : PathHelper.GetExt(fileName);

        if (span.Length < handler.MinValidSize)
            throw new InvalidDataException($"The provided data is {span.Length} bytes. The data must be at least {handler.MinValidSize} bytes.");

        if (!skipExtCheck && ext != null && !handler.ValidExt.Contains(ext))
            throw new InvalidDataException($"The extension '{ext}' is not valid.");

        if (!handler.IsValidHeader(span))
            throw new InvalidDataException("The header is not valid.");
    }
}