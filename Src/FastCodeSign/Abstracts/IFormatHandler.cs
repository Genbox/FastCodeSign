using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using Genbox.FastCodeSign.Models;

namespace Genbox.FastCodeSign.Abstracts;

/// <summary>
/// This is the low-level API for format handlers.
/// It provides implementers with a small cross-section of responsibilities when implementing a handler.
/// </summary>
public interface IFormatHandler
{
    int MinValidSize { get; }
    string[] ValidExt { get; }
    bool IsValidHeader(ReadOnlySpan<byte> data);

    IContext GetContext(ReadOnlySpan<byte> data);

    /// <summary>Extracts the range of bytes that represent the CMS blob</summary>
    ReadOnlySpan<byte> ExtractSignature(IContext context, ReadOnlySpan<byte> data);

    /// <summary>Extracts every CMS blob represented by the format. Normal formats contain one CMS.</summary>
    IReadOnlyList<byte[]> ExtractSignatures(IContext context, ReadOnlySpan<byte> data) => [ExtractSignature(context, data).ToArray()];

    /// <summary>Computes a hash of the data as defined by the signing specification.</summary>
    byte[] ComputeHash(IContext context, ReadOnlySpan<byte> data, HashAlgorithmName hashAlgorithm);

    /// <summary>Computes the hash for a CMS extracted at <paramref name="signatureIndex"/>.</summary>
    byte[] ComputeHash(IContext context, ReadOnlySpan<byte> data, HashAlgorithmName hashAlgorithm, int signatureIndex)
        => ComputeHash(context, data, hashAlgorithm);

    /// <summary>Remove the signature from the data.</summary>
    /// <returns>The number of bytes removed. It is used by the higher-level APIs for truncation of the file.</returns>
    long RemoveSignature(IContext context, Span<byte> data);

    /// <summary>
    /// Removes a signature and resizes the allocation. This low-level operation mutates the allocation immediately.
    /// Callers that require atomic replacement should stage work in a separate allocation first.
    /// </summary>
    long RemoveSignature(IContext context, IAllocation allocation)
    {
        Span<byte> data = allocation.GetSpan();
        long delta = RemoveSignature(context, data);
        allocation.SetLength(checked((uint)(data.Length - delta)));
        return delta;
    }

    /// <summary>The handler can add properties to the CMS signer object which are needed to envelope the signature.</summary>
    /// <param name="context">The context</param>
    /// <param name="data">The data</param>
    /// <param name="signOptions"></param>
    /// <param name="formatOptions"></param>
    /// <param name="configureSigner">An action to modify the CmsSigner object before signing</param>
    /// <returns>The ContentInfo object to sign in the CMS structure</returns>
    Signature CreateSignature(IContext context, ReadOnlySpan<byte> data, SignOptions signOptions, IFormatOptions? formatOptions = null, Action<CmsSigner>? configureSigner = null);

    /// <summary>Writes the encoded CMS structure into a signature structure.</summary>
    void WriteSignature(IContext context, IAllocation allocation, Signature signature);

    /// <summary>Verifies the CMS signature bytes independently of certificate trust.</summary>
    void CheckSignature(IContext context, ReadOnlySpan<byte> data, SignedCms signedCms)
    {
        if (signedCms.SignerInfos.Count == 0)
            throw new CryptographicException("The CMS does not contain a signer.");

        signedCms.CheckSignature(true);
    }

    /// <summary>Extracts the hash from a signed CMS structure. File formats usually save it in an attribute or as part of the ContentInfo.</summary>
    /// <param name="signedCms">The CMS structure</param>
    /// <param name="digest">The digest</param>
    /// <param name="algo">The algorithm that was used to originally create the digest</param>
    /// <returns>True, if it was possible to find the hash, otherwise false.</returns>
    bool ExtractHashFromSignedCms(SignedCms signedCms, [NotNullWhen(true)]out byte[]? digest, out HashAlgorithmName algo);
}