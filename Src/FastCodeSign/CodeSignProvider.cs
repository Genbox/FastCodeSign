using System.Diagnostics;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Genbox.FastCodeSign.Abstracts;
using Genbox.FastCodeSign.Allocations;
using Genbox.FastCodeSign.Enums;
using Genbox.FastCodeSign.Extensions;
using Genbox.FastCodeSign.Handlers;
using Genbox.FastCodeSign.Internal;
using Genbox.FastCodeSign.Internal.Helpers;
using Genbox.FastCodeSign.Models;

namespace Genbox.FastCodeSign;

public class CodeSignProvider
{
    private const string Rfc3161TimestampTokenOid = "1.2.840.113549.1.9.16.2.14";
    private const string TimeStampingEkuOid = "1.3.6.1.5.5.7.3.8";
    private const int MaximumVerificationDepth = 16;
    private const int MaximumVerifiedSigners = 256;
    private readonly string? _fileName;
    private readonly IFormatHandler _handler;

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

        try
        {
            ReadOnlySpan<byte> span = allocation.GetSpan();

            if (handler == null)
                handler = GetFormatHandler(span, ext, skipExtCheck);
            else
                ValidateHandler(handler, span, ext, skipExtCheck);

            return new CodeSignFileProvider(handler, allocation, fileName);
        }
        catch
        {
            allocation.Dispose();
            throw;
        }
    }

    public static CodeSignBundleProvider FromBundle(string path, IBundleHandler? handler = null)
    {
        if (handler == null)
            handler = GetBundleHandler(path);
        else
            ValidateBundleHandler(handler, path);

        return new CodeSignBundleProvider(handler, path);
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

    public SignedCms? GetSignature() => GetSignatures().FirstOrDefault();

    /// <summary>Gets every embedded CMS signature. Universal Mach-O files return one CMS for each architecture.</summary>
    public IReadOnlyList<SignedCms> GetSignatures()
    {
        ReadOnlySpan<byte> data = Allocation.GetSpan();
        IContext context = _handler.GetContext(data);

        if (!context.IsSigned)
            return [];

        IReadOnlyList<byte[]> signatureBytes = _handler.ExtractSignatures(context, data);
        List<SignedCms> signatures = new List<SignedCms>(signatureBytes.Count);

        foreach (byte[] bytes in signatureBytes)
        {
            Debug.Assert(bytes.Length != 0);
            signatures.Add(DecodeSignature(context, data, bytes));
        }

        return signatures;
    }

    public bool HasValidSignature(SignedCms signedCms)
    {
        Span<byte> span = Allocation.GetSpan();

        IContext context = _handler.GetContext(span);

        if (!context.IsSigned)
            throw new InvalidOperationException("The file is not signed.");

        try
        {
            // FCS-001: Digest equality cannot substitute for verification of every CMS signer.
            _handler.CheckSignature(context, span, signedCms);
        }
        catch (CryptographicException)
        {
            return false;
        }

        if (!_handler.ExtractHashFromSignedCms(signedCms, out byte[]? expectedDigest, out HashAlgorithmName hashAlgorithm))
            throw new InvalidOperationException("The CMS does not contain a valid hash.");

        int signatureIndex = 0;
        byte[] encoded = signedCms.Encode();
        IReadOnlyList<byte[]> signatures = _handler.ExtractSignatures(context, span);

        for (int i = 0; i < signatures.Count; i++)
        {
            if (signatures[i].AsSpan().SequenceEqual(encoded))
            {
                signatureIndex = i;
                break;
            }
        }

        byte[] actualDigest = _handler.ComputeHash(context, span, hashAlgorithm, signatureIndex);
        return expectedDigest.SequenceEqual(actualDigest);
    }

    /// <summary>
    /// Verifies format/content integrity and then evaluates every CMS signer's certificate with managed X509 chain building.
    /// This is not equivalent to Windows WinVerifyTrust, macOS Gatekeeper, or any platform execution policy.
    /// </summary>
    public CodeSignVerificationResult VerifySignature(CodeSignVerificationOptions? options = null)
    {
        options ??= new CodeSignVerificationOptions();

        ReadOnlySpan<byte> data = Allocation.GetSpan();
        IContext context = _handler.GetContext(data);
        if (!context.IsSigned)
            return new CodeSignVerificationResult(SignatureIntegrityStatus.NotSigned, CertificateTrustStatus.NotChecked, [], "The file is not signed.");

        IReadOnlyList<byte[]> signatureBytes;

        try
        {
            signatureBytes = _handler.ExtractSignatures(context, data);
            if (signatureBytes.Count == 0 || signatureBytes.Any(static signature => signature.Length == 0))
                return new CodeSignVerificationResult(SignatureIntegrityStatus.Invalid, CertificateTrustStatus.NotChecked, [], "The signature is empty.");

            for (int i = 0; i < signatureBytes.Count; i++)
            {
                SignedCms signedCms = DecodeSignature(context, data, signatureBytes[i]);
                if (!_handler.ExtractHashFromSignedCms(signedCms, out byte[]? expectedDigest, out HashAlgorithmName hashAlgorithm) || !expectedDigest.SequenceEqual(_handler.ComputeHash(context, data, hashAlgorithm, i)))
                    return new CodeSignVerificationResult(SignatureIntegrityStatus.Invalid, CertificateTrustStatus.NotChecked, [], "The signed digest does not match the file content.");
            }
        }
        catch (Exception ex) when (ex is CryptographicException or InvalidDataException or ArgumentException)
        {
            return new CodeSignVerificationResult(SignatureIntegrityStatus.Invalid, CertificateTrustStatus.NotChecked, [], ex.Message);
        }

        List<SignerVerificationResult> signers = new List<SignerVerificationResult>();

        try
        {
            VerificationTraversal traversal = new VerificationTraversal();
            for (int i = 0; i < signatureBytes.Count; i++)
                VerifyCms(context, data, DecodeSignature(context, data, signatureBytes[i]), i, options, signers, traversal, 0, false);
        }
        catch (Exception ex) when (ex is CryptographicException or InvalidDataException or ArgumentException)
        {
            return new CodeSignVerificationResult(SignatureIntegrityStatus.Invalid, CertificateTrustStatus.NotChecked, [], ex.Message);
        }

        CertificateTrustStatus trustStatus = signers.Count != 0 && signers.TrueForAll(static signer => signer.TrustStatus == CertificateTrustStatus.Trusted)
            ? CertificateTrustStatus.Trusted
            : CertificateTrustStatus.Untrusted;
        return new CodeSignVerificationResult(SignatureIntegrityStatus.Valid, trustStatus, signers, null);
    }

    public byte[] ComputeHash(HashAlgorithmName? hashAlgorithm = null)
    {
        Span<byte> data = Allocation.GetSpan();
        IContext context = _handler.GetContext(data);
        return _handler.ComputeHash(context, data, hashAlgorithm ?? HashAlgorithmName.SHA256);
    }

    private void VerifyCms(IContext context, ReadOnlySpan<byte> data, SignedCms signedCms, int signatureIndex, CodeSignVerificationOptions options, List<SignerVerificationResult> signers, VerificationTraversal traversal, int depth, bool nested)
    {
        if (depth > MaximumVerificationDepth)
            throw new InvalidDataException("The nested CMS signature depth exceeds the supported limit.");

        if (nested && !traversal.NestedCms.Add(Convert.ToHexString(SHA256.HashData(signedCms.Encode()))))
            throw new InvalidDataException("The CMS signature contains a repeated nested signature.");

        if (nested)
        {
            _handler.CheckSignature(context, data, signedCms);
            if (!_handler.ExtractHashFromSignedCms(signedCms, out byte[]? expectedDigest, out HashAlgorithmName hashAlgorithm) || !expectedDigest.SequenceEqual(_handler.ComputeHash(context, data, hashAlgorithm, signatureIndex)))
                throw new CryptographicException("The nested CMS digest does not match the file content.");
        }

        foreach (SignerInfo signerInfo in signedCms.SignerInfos)
            VerifySigner(context, data, signerInfo, signedCms.Certificates, signatureIndex, options, signers, traversal, depth);
    }

    private void VerifySigner(IContext context, ReadOnlySpan<byte> data, SignerInfo signerInfo, X509Certificate2Collection certificates, int signatureIndex, CodeSignVerificationOptions options, List<SignerVerificationResult> signers, VerificationTraversal traversal, int depth)
    {
        if (depth > MaximumVerificationDepth)
            throw new InvalidDataException("The CMS signer depth exceeds the supported limit.");

        if (++traversal.SignerCount > MaximumVerifiedSigners)
            throw new InvalidDataException("The CMS signature contains too many signers.");

        List<TimestampVerificationResult> timestamps = VerifyTimestamps(signerInfo, options);
        X509Certificate2? certificate = signerInfo.Certificate;

        if (certificate == null)
            signers.Add(new SignerVerificationResult(null, CertificateTrustStatus.NoCertificate, [], timestamps, "The signer certificate is not present in the CMS."));
        else
        {
            DateTime? verificationTime = options.VerificationTime;

            if (options.UseTimestampTime)
            {
                TimestampVerificationResult? timestamp = timestamps.FirstOrDefault(static result => result.Status == TimestampVerificationStatus.Trusted);
                if (timestamp?.Timestamp is DateTimeOffset timestampTime)
                    verificationTime = timestampTime.UtcDateTime;
            }

            try
            {
                bool trusted = BuildChain(certificate, certificates, options, verificationTime, options.ApplicationPolicyOids, out X509ChainStatus[] statuses);
                signers.Add(new SignerVerificationResult(certificate, trusted ? CertificateTrustStatus.Trusted : CertificateTrustStatus.Untrusted, statuses, timestamps, trusted ? null : "The signer certificate chain is not trusted."));
            }
            catch (Exception ex) when (ex is CryptographicException or ArgumentException)
            {
                signers.Add(new SignerVerificationResult(certificate, CertificateTrustStatus.Untrusted, [], timestamps, ex.Message));
            }
        }

        foreach (SignerInfo counterSigner in signerInfo.CounterSignerInfos)
        {
            counterSigner.CheckSignature(true);
            VerifySigner(context, data, counterSigner, certificates, signatureIndex, options, signers, traversal, depth + 1);
        }

        foreach (CryptographicAttributeObject attribute in signerInfo.UnsignedAttributes)
        {
            if (attribute.Oid.Value != OidConstants.MsNestedSignature)
                continue;

            foreach (AsnEncodedData value in attribute.Values)
                VerifyCms(context, data, DecodeNestedCms(value.RawData), signatureIndex, options, signers, traversal, depth + 1, true);
        }
    }

    private static List<TimestampVerificationResult> VerifyTimestamps(SignerInfo signerInfo, CodeSignVerificationOptions options)
    {
        List<TimestampVerificationResult> results = new List<TimestampVerificationResult>();

        foreach (CryptographicAttributeObject attribute in signerInfo.UnsignedAttributes)
        {
            if (attribute.Oid.Value != OidConstants.MsCounterSign && attribute.Oid.Value != Rfc3161TimestampTokenOid)
                continue;

            foreach (AsnEncodedData value in attribute.Values)
            {
                if (!Rfc3161TimestampToken.TryDecode(value.RawData, out Rfc3161TimestampToken? token, out _))
                {
                    results.Add(new TimestampVerificationResult(TimestampVerificationStatus.Invalid, null, null, [], "The RFC3161 timestamp token is invalid."));
                    continue;
                }

                try
                {
                    SignedCms timestampCms = token.AsSignedCms();
                    bool valid = token.VerifySignatureForSignerInfo(signerInfo, out X509Certificate2? certificate, timestampCms.Certificates);

                    if (!valid || certificate == null)
                    {
                        results.Add(new TimestampVerificationResult(TimestampVerificationStatus.Invalid, token.TokenInfo.Timestamp, certificate, [], "The RFC3161 timestamp does not match the signer."));
                        continue;
                    }

                    if (!HasRfc3161CertificateProfile(certificate))
                    {
                        results.Add(new TimestampVerificationResult(TimestampVerificationStatus.Invalid, token.TokenInfo.Timestamp, certificate, [], "The timestamp authority certificate does not have the required RFC3161 extended key usage profile."));
                        continue;
                    }

                    bool trusted = BuildChain(certificate, timestampCms.Certificates, options, token.TokenInfo.Timestamp.UtcDateTime, [TimeStampingEkuOid], out X509ChainStatus[] statuses);
                    results.Add(new TimestampVerificationResult(trusted ? TimestampVerificationStatus.Trusted : TimestampVerificationStatus.Untrusted, token.TokenInfo.Timestamp, certificate, statuses, trusted ? null : "The timestamp authority certificate chain is not trusted."));
                }
                catch (Exception ex) when (ex is CryptographicException or ArgumentException)
                {
                    results.Add(new TimestampVerificationResult(TimestampVerificationStatus.Invalid, null, null, [], ex.Message));
                }
            }
        }

        return results;
    }

    private static SignedCms DecodeNestedCms(ReadOnlySpan<byte> encoded)
    {
        if (!AsnDecoder.TryReadEncodedValue(encoded, AsnEncodingRules.BER, out Asn1Tag tag, out _, out _, out int bytesConsumed) || !tag.HasSameClassAndValue(Asn1Tag.Sequence) || encoded.Length != bytesConsumed)
            throw new InvalidDataException("The nested CMS signature is malformed.");

        SignedCms nestedCms = new SignedCms();
        nestedCms.Decode(encoded);
        return nestedCms;
    }

    private static bool HasRfc3161CertificateProfile(X509Certificate2 certificate)
    {
        X509EnhancedKeyUsageExtension[] ekuExtensions = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().ToArray();
        return ekuExtensions.Length == 1 && ekuExtensions[0].Critical && ekuExtensions[0].EnhancedKeyUsages.Count == 1 && ekuExtensions[0].EnhancedKeyUsages[0].Value == TimeStampingEkuOid;
    }

    private static bool BuildChain(X509Certificate2 certificate, X509Certificate2Collection extraCertificates, CodeSignVerificationOptions options, DateTime? verificationTime, IEnumerable<string> applicationPolicyOids, out X509ChainStatus[] statuses)
    {
        using X509Chain chain = new X509Chain();
        X509ChainPolicy policy = chain.ChainPolicy;
        policy.RevocationMode = options.RevocationMode;
        policy.RevocationFlag = options.RevocationFlag;
        policy.TrustMode = options.TrustMode;
        policy.ExtraStore.AddRange(extraCertificates);
        foreach (X509Certificate2 root in options.CustomTrustRoots)
            policy.CustomTrustStore.Add(root);
        foreach (string oid in applicationPolicyOids)
            policy.ApplicationPolicy.Add(new Oid(oid));
        if (verificationTime.HasValue)
            policy.VerificationTime = verificationTime.Value;

        bool trusted = chain.Build(certificate);
        statuses = chain.ChainStatus.ToArray();
        return trusted;
    }

    /// <summary>Removes the current signature immediately. This low-level operation mutates the provider allocation.</summary>
    public bool TryRemoveSignature(bool truncate)
    {
        Span<byte> data = Allocation.GetSpan();
        IContext context = _handler.GetContext(data);

        if (!context.IsSigned)
            return false;

        if (truncate)
            _handler.RemoveSignature(context, Allocation);
        else
            _handler.RemoveSignature(context, data);

        return true;
    }

    public Signature CreateSignature(SignOptions signOptions, IFormatOptions? formatOptions = null, Action<CmsSigner>? configureSigner = null)
    {
        Span<byte> data = Allocation.GetSpan();
        IContext context = _handler.GetContext(data);

        if (context.IsSigned)
            throw new InvalidOperationException("The file already contains a signature.");

        //Small hack to transfer the filename to the MachObjectFormatHandler if user didn't set the format options, but provided a filename.
        if (formatOptions == null && _fileName != null && _handler is MachObjectFormatHandler or FatMachObjectFormatHandler)
            return _handler.CreateSignature(context, data, signOptions, new MachObjectFormatOptions { Identifier = _fileName }, configureSigner);

        return _handler.CreateSignature(context, data, signOptions, formatOptions, configureSigner);
    }

    /// <summary>Writes a signature immediately. This low-level operation mutates the provider allocation.</summary>
    public void WriteSignature(Signature signature)
    {
        Span<byte> data = Allocation.GetSpan();
        IContext context = _handler.GetContext(data);

        if (context.IsSigned)
            throw new InvalidOperationException("The file already contains a signature.");

        _handler.WriteSignature(context, Allocation, signature);
    }

    /// <summary>
    /// Creates, optionally timestamps, and writes a signature. Replacement is staged in memory so the allocation is not changed until the complete replacement is ready.
    /// </summary>
    public async Task SignAsync(SignOptions signOptions, IFormatOptions? formatOptions = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signOptions);
        cancellationToken.ThrowIfCancellationRequested();

        MemoryAllocation stagedAllocation = new MemoryAllocation(Allocation.GetSpan().ToArray());
        CodeSignProvider stagedProvider = new CodeSignProvider(_handler, stagedAllocation, _fileName);

        if (stagedProvider.HasSignature())
        {
            if (signOptions.ExistingSignatureBehavior == ExistingSignatureBehavior.Fail)
                throw new InvalidOperationException("The file already contains a signature.");
            stagedProvider.TryRemoveSignature(true);
        }

        Signature signature = stagedProvider.CreateSignature(signOptions, formatOptions);
        if (signOptions.Timestamp != null)
            await signature.ApplyTimestampAsync(signOptions.Timestamp, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        stagedProvider.WriteSignature(signature);

        byte[] result = stagedAllocation.GetSpan().ToArray();
        Allocation.SetLength((uint)result.Length);
        result.CopyTo(Allocation.GetSpan());
    }

    private SignedCms DecodeSignature(IContext context, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signatureBytes)
    {
        if (AsnDecoder.TryReadEncodedValue(signatureBytes, AsnEncodingRules.BER, out Asn1Tag tag, out _, out _, out int bytesConsumed))
        {
            if (!tag.HasSameClassAndValue(Asn1Tag.Sequence))
                throw new InvalidOperationException("The ASN.1 structure is invalid");
            if (signatureBytes.Length != bytesConsumed)
                throw new InvalidDataException("There is trailing data after the ASN.1 structure");
        }

        SignedCms signedCms = new SignedCms();
        signedCms.Decode(signatureBytes);
        _handler.CheckSignature(context, data, signedCms);
        return signedCms;
    }

    private static IFormatHandler GetFormatHandler(ReadOnlySpan<byte> span, string? ext, bool skipExtCheck)
    {
        IFormatHandler? factory = FormatHandlerFactory.Get(span, ext, skipExtCheck);

        if (factory == null)
            throw new InvalidOperationException("Unable to find a valid handler");

        return factory;
    }

    private static IBundleHandler GetBundleHandler(string path)
    {
        IBundleHandler? factory = BundleHandlerFactory.Get(path);

        if (factory == null)
            throw new InvalidOperationException("Unable to find a valid handler");

        return factory;
    }

    private static void ValidateHandler(IFormatHandler handler, ReadOnlySpan<byte> span, string? ext, bool skipExtCheck)
    {
        if (span.Length < handler.MinValidSize)
            throw new InvalidDataException($"The provided data is {span.Length} bytes. The data must be at least {handler.MinValidSize} bytes.");

        if (!skipExtCheck && ext != null && handler.ValidExt.Length != 0 && !handler.ValidExt.Contains(ext))
            throw new InvalidDataException($"The extension '{ext}' is not valid.");

        if (!handler.IsValidHeader(span))
            throw new InvalidDataException("The header is not valid.");
    }

    private static void ValidateBundleHandler(IBundleHandler handler, string path)
    {
        if (!handler.IsBundlePath(path))
            throw new InvalidDataException($"The provided handler does not support the files in '{path}'");
    }

    private sealed class VerificationTraversal
    {
        internal HashSet<string> NestedCms { get; } = new HashSet<string>(StringComparer.Ordinal);
        internal int SignerCount { get; set; }
    }
}