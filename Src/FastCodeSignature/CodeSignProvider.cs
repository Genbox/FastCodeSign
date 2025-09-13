using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using Genbox.FastCodeSignature.Abstracts;

namespace Genbox.FastCodeSignature;

public sealed class CodeSignProvider : IDisposable
{
    private readonly IAllocation _allocation;
    private readonly IFormatHandler _handler;

    internal CodeSignProvider(IFormatHandler handler, IAllocation allocation)
    {
        _handler = handler;
        _allocation = allocation;
    }

    [SuppressMessage("IDisposableAnalyzers.Correctness", "IDISP007:Don\'t dispose injected", Justification = "This is the only reference to the allocation that is given to the user")]
    public void Dispose() => _allocation.Dispose();

    public SignedCms? GetSignature()
    {
        Span<byte> data = _allocation.GetSpan();

        ReadOnlySpan<byte> signature = _handler.ExtractSignature(data);

        if (signature.IsEmpty)
            return null;

        SignedCms signedCms = new SignedCms();
        signedCms.Decode(signature);
        return signedCms;
    }

    public bool HasValidSignature(SignedCms signedCms)
    {
        Span<byte> span = _allocation.GetSpan();

        if (!_handler.TryGetHash(signedCms, out byte[]? expectedDigest, out HashAlgorithmName hashAlgorithm))
            return false;

        byte[] actualDigest = _handler.ComputeHash(span, hashAlgorithm);
        return expectedDigest.SequenceEqual(actualDigest);
    }

    public byte[] ComputeHash(HashAlgorithmName? hashAlgorithm = null)
    {
        Span<byte> data = _allocation.GetSpan();

        return _handler.ComputeHash(data, hashAlgorithm ?? HashAlgorithmName.SHA256);
    }

    public ReadOnlySpan<byte> RemoveSignature(bool truncate)
    {
        Span<byte> data = _allocation.GetSpan();
        long delta = _handler.RemoveSignature(data);

        if (truncate)
            _allocation.SetLength((uint)(data.Length - delta));

        return _allocation.GetSpan();
    }

    public Signature CreateSignature(HashAlgorithmName? hashAlgorithm = null)
    {
        hashAlgorithm ??= HashAlgorithmName.SHA256;
        return _handler.CreateSignature(_allocation.GetSpan(), hashAlgorithm.Value);
    }

    public ReadOnlySpan<byte> WriteSignature(Signature signature)
    {
        _handler.WriteSignature(_allocation, signature);
        return _allocation.GetSpan();
    }

    public void WriteSignatureToPemFile(string output)
    {
        SignedCms? cms = GetSignature();

        if (cms == null)
            throw new InvalidOperationException("The source file does not have a signature");

        File.WriteAllText(output, PemEncoding.WriteString("PKCS7", cms.Encode()));
    }
}