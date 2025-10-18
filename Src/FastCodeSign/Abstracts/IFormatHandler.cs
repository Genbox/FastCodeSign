using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
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

    /// <summary>Computes a hash of the data as defined by the signing specification.</summary>
    byte[] ComputeHash(IContext context, ReadOnlySpan<byte> data, HashAlgorithmName hashAlgorithm);

    /// <summary>Remove the signature from the data.</summary>
    /// <returns>The number of bytes removed. It is used by the higher-level APIs for truncation of the file.</returns>
    long RemoveSignature(IContext context, Span<byte> data);

    /// <summary>Writes the encoded CMS structure into a signature structure.</summary>
    void WriteSignature(IContext context, IAllocation allocation, Signature signature);

    /// <summary>The handler can add properties to the CMS signer object which are needed to envelope the signature.</summary>
    /// <param name="context">The context</param>
    /// <param name="data">The data</param>
    /// <param name="privateKey">The private key to use</param>
    /// <param name="hashAlgorithm">The hash algorithm to use when creating the signature</param>
    /// <param name="configureSigner">An action to modify the CmsSigner object before signing</param>
    /// <param name="cert">The certificate to sign with</param>
    /// <param name="silent">A bool indicating if the underlying key provider can ask for PIN or not</param>
    /// <returns>The ContentInfo object to sign in the CMS structure</returns>
    Signature CreateSignature(IContext context, ReadOnlySpan<byte> data, X509Certificate2 cert, AsymmetricAlgorithm? privateKey, HashAlgorithmName hashAlgorithm, Action<CmsSigner>? configureSigner, bool silent);

    /// <summary>Extracts the hash from a signed CMS structure. File formats usually save it in an attribute or as part of the ContentInfo.</summary>
    /// <param name="signedCms">The CMS structure</param>
    /// <param name="digest">The digest</param>
    /// <param name="algo">The algorithm that was used to originally create the digest</param>
    /// <returns>True, if it was possible to find the hash, otherwise false.</returns>
    bool ExtractHashFromSignedCms(SignedCms signedCms, [NotNullWhen(true)]out byte[]? digest, out HashAlgorithmName algo);
}