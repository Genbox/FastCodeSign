using System.Diagnostics;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using Genbox.FastCodeSign.Abstracts;
using Genbox.FastCodeSign.Allocations;
using Genbox.FastCodeSign.Handlers;
using Genbox.FastCodeSign.Internal;
using Genbox.FastCodeSign.Internal.Helpers;
using Genbox.FastCodeSign.Models;

namespace Genbox.FastCodeSign;

public class CodeSignProvider
{
    private readonly IFormatHandler _handler;
    private readonly string? _fileName;

    internal CodeSignProvider(IFormatHandler handler, IAllocation allocation, string? fileName)
    {
        _handler = handler;
        _fileName = fileName;
        Allocation = allocation;
    }

    internal IAllocation Allocation { get; }

    public static CodeSignFileProvider FromFile(string filePath, IFormatHandler? handler = null, bool skipExtCheck = false)
    {
        FileAllocation allocation = new FileAllocation(filePath); //We don't dispose this here. Instead, we let CodeSignFileProvider do it

        string fileName = Path.GetFileName(filePath);
        string? ext = PathHelper.GetExt(fileName);

        ReadOnlySpan<byte> span = allocation.GetSpan();

        if (handler == null)
            handler = GetFormatHandler(span, ext, skipExtCheck);
        else
            ValidateHandler(handler, span, ext, skipExtCheck);

        return new CodeSignFileProvider(handler, allocation, fileName);
    }

    public static CodeSignProvider FromData(byte[] data, IFormatHandler? handler = null, string? fileName = null, bool skipExtCheck = false)
    {
        MemoryAllocation allocation = new MemoryAllocation(data);
        return FromAllocation(allocation, handler, fileName, skipExtCheck);
    }

    public static CodeSignProvider FromAllocation(IAllocation allocation, IFormatHandler? handler = null, string? fileName = null, bool skipExtCheck = false)
    {
        ReadOnlySpan<byte> span = allocation.GetSpan();
        string? ext = fileName == null ? null : PathHelper.GetExt(fileName);

        if (handler == null)
            handler = GetFormatHandler(span, ext, skipExtCheck);
        else
            ValidateHandler(handler, span, ext, skipExtCheck);

        return new CodeSignProvider(handler, allocation, fileName);
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

        // Extra sanity checks before delegating decoding to SignedCms
        if (AsnDecoder.TryReadEncodedValue(signatureBytes, AsnEncodingRules.BER, out Asn1Tag tag, out _, out _, out int bytesConsumed))
        {
            if (!tag.HasSameClassAndValue(Asn1Tag.Sequence))
                throw new InvalidOperationException("The ASN.1 structure is invalid");

            if (signatureBytes.Length != bytesConsumed)
                throw new InvalidDataException("There is trailing data after the ASN.1 structure");
        }

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

    public Signature CreateSignature(SignOptions signOptions, IFormatOptions? formatOptions = null, Action<CmsSigner>? configureSigner = null)
    {
        Span<byte> data = Allocation.GetSpan();
        IContext context = _handler.GetContext(data);

        if (context.IsSigned)
            throw new InvalidOperationException("The file already contains a signature.");

        //Small hack to transfer the filename to the MachObjectFormatHandler if user didn't set the format options, but provided a filename.
        if (formatOptions == null && _fileName != null && _handler is MachObjectFormatHandler machHandler)
            return ((IFormatHandler)machHandler).CreateSignature(context, data, signOptions, new MachObjectFormatOptions { Identifier = _fileName }, configureSigner);

        return _handler.CreateSignature(context, data, signOptions, formatOptions, configureSigner);
    }

    public void WriteSignature(Signature signature)
    {
        Span<byte> data = Allocation.GetSpan();
        IContext context = _handler.GetContext(data);

        if (context.IsSigned)
            throw new InvalidOperationException("The file already contains a signature.");

        _handler.WriteSignature(context, Allocation, signature);
    }

    private static IFormatHandler GetFormatHandler(ReadOnlySpan<byte> span, string? ext, bool skipExtCheck)
    {
        IFormatHandler? factory = FormatHandlerFactory.Get(span, ext, skipExtCheck);

        if (factory == null)
            throw new InvalidOperationException("Unable to find a valid handler");

        return factory;
    }

    private static void ValidateHandler(IFormatHandler handler, ReadOnlySpan<byte> span, string? ext, bool skipExtCheck)
    {
        if (span.Length < handler.MinValidSize)
            throw new InvalidDataException($"The provided data is {span.Length} bytes. The data must be at least {handler.MinValidSize} bytes.");

        if (!skipExtCheck && ext != null && !handler.ValidExt.Contains(ext))
            throw new InvalidDataException($"The extension '{ext}' is not valid.");

        if (!handler.IsValidHeader(span))
            throw new InvalidDataException("The header is not valid.");
    }
}