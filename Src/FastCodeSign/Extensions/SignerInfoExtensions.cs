using System.Buffers;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Genbox.FastCodeSign.Internal;
using Genbox.FastCodeSign.Internal.Helpers;
using Genbox.FastCodeSign.Models;

namespace Genbox.FastCodeSign.Extensions;

public static class SignerInfoExtensions
{
    private const string Rfc3161TimestampTokenOid = "1.2.840.113549.1.9.16.2.14";

    /// <summary>
    /// Returns a list of RFC3161 counter-signatures
    /// </summary>
    /// <returns>A list of counter-signatures</returns>
    /// <exception cref="InvalidOperationException">If the file contains invalid counter-signatures</exception>
    public static IEnumerable<CounterSignature> GetCounterSignatures(this SignerInfo signerInfo)
    {
        // PKCS#9 counter signatures
        foreach (SignerInfo info in signerInfo.CounterSignerInfos)
        {
            X509Certificate2? cert = info.Certificate;
            if (cert == null)
                throw new InvalidOperationException("The counter signature does not contain a certificate.");

            string? digestAlgorithm = info.DigestAlgorithm.Value;
            if (digestAlgorithm == null)
                throw new InvalidOperationException("The counter signature does not contain a digest algorithm.");

            DateTime signingTime = DateTime.MinValue;
            foreach (CryptographicAttributeObject attr in info.SignedAttributes)
            {
                foreach (AsnEncodedData value in attr.Values)
                {
                    if (value is Pkcs9SigningTime time)
                        signingTime = time.SigningTime.ToUniversalTime();
                }
            }

            yield return new CounterSignature(cert, OidHelper.OidToHashAlgorithm(digestAlgorithm), signingTime);
        }

        // RFC3161 (Time-Stamp Protocol)
        foreach (CryptographicAttributeObject attr in signerInfo.UnsignedAttributes)
        {
            if (attr.Oid.Value != OidConstants.MsCounterSign && attr.Oid.Value != Rfc3161TimestampTokenOid)
                continue;

            foreach (AsnEncodedData value in attr.Values)
            {
                if (!Rfc3161TimestampToken.TryDecode(value.RawData, out Rfc3161TimestampToken? token, out _))
                    throw new InvalidOperationException("The counter signature does not contain a valid token.");

                SignedCms cms = token.AsSignedCms();

                if (cms.SignerInfos.Count == 0)
                    throw new InvalidOperationException("The counter signature does not contain any signer infos.");

                X509Certificate2? cert = cms.SignerInfos[0].Certificate;
                if (cert == null)
                    throw new InvalidOperationException("The counter signature does not contain a certificate.");

                Rfc3161TimestampTokenInfo info = token.TokenInfo;
                string? digestAlgorithm = info.HashAlgorithmId.Value;
                if (digestAlgorithm == null)
                    throw new InvalidOperationException("The counter signature does not contain a digest algorithm.");

                yield return new CounterSignature(cert, OidHelper.OidToHashAlgorithm(digestAlgorithm), info.Timestamp.UtcDateTime);
            }
        }
    }

    /// <summary>Extracts nested signatures from a SignerInfo</summary>
    /// <returns>Nested signatures</returns>
    public static IEnumerable<SignedCms> GetNestedSignatures(this SignerInfo signerInfo)
    {
        foreach (CryptographicAttributeObject attr in signerInfo.UnsignedAttributes)
        {
            if (attr.Oid.Value != OidConstants.MsNestedSignature)
                continue;

            foreach (AsnEncodedData sig in attr.Values)
            {
                SignedCms nested = new SignedCms();
                nested.Decode(sig.RawData);
                yield return nested;
            }
        }
    }

    /// <summary>
    /// Countersign a SignerInfo using RFC3161.
    /// </summary>
    /// <param name="signerInfo">The signer info</param>
    /// <param name="url">The URL of the timestamp server</param>
    /// <param name="hashAlgorithm">The hashing algorithm to use</param>
    public static Task CounterSignAsync(this SignerInfo signerInfo, string url, HashAlgorithmName hashAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(url);
        return CounterSignAsync(signerInfo, new Uri(url, UriKind.Absolute), hashAlgorithm, null, CancellationToken.None);
    }

    /// <summary>
    /// Countersign a SignerInfo using RFC3161.
    /// </summary>
    /// <param name="signerInfo">The signer info</param>
    /// <param name="timestampAuthorityUri">The URI of the timestamp server</param>
    /// <param name="hashAlgorithm">The hashing algorithm to use</param>
    /// <param name="httpClient">The HTTP client to use, or null to create one for this request</param>
    /// <param name="cancellationToken">The cancellation token for the request</param>
    public static async Task CounterSignAsync(this SignerInfo signerInfo, Uri timestampAuthorityUri, HashAlgorithmName hashAlgorithm, HttpClient? httpClient = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signerInfo);
        ArgumentNullException.ThrowIfNull(timestampAuthorityUri);

        HttpClient client = httpClient ?? new HttpClient();
        HttpClient? ownedClient = httpClient == null ? client : null;
        try
        {
            AsnEncodedData attribute = await GetTimestampAttributeAsync(signerInfo, timestampAuthorityUri, hashAlgorithm, client, cancellationToken).ConfigureAwait(false);
            signerInfo.AddUnsignedAttribute(attribute);
        }
        finally
        {
            ownedClient?.Dispose();
        }
    }

    internal static async Task<AsnEncodedData> GetTimestampAttributeAsync(this SignerInfo signerInfo, Uri timestampAuthorityUri, HashAlgorithmName hashAlgorithm, HttpClient httpClient, CancellationToken cancellationToken)
    {
        return await GetTimestampAttributeAsync(signerInfo, timestampAuthorityUri, hashAlgorithm, httpClient, TimestampOptions.DefaultMaximumResponseSizeBytes, false, cancellationToken).ConfigureAwait(false);
    }

    internal static async Task<AsnEncodedData> GetTimestampAttributeAsync(this SignerInfo signerInfo, Uri timestampAuthorityUri, HashAlgorithmName hashAlgorithm, HttpClient httpClient, int maximumResponseSizeBytes, bool requireResponseContentType, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(signerInfo);
        ArgumentNullException.ThrowIfNull(timestampAuthorityUri);
        ArgumentNullException.ThrowIfNull(httpClient);
        cancellationToken.ThrowIfCancellationRequested();

        using RandomNumberGenerator rng = RandomNumberGenerator.Create();
        byte[] nonce = new byte[8];
        rng.GetBytes(nonce);

        Rfc3161TimestampRequest request = Rfc3161TimestampRequest.CreateFromSignerInfo(signerInfo, hashAlgorithm, null, nonce, true);
        using ByteArrayContent content = new ByteArrayContent(request.Encode());
        content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-query");

        byte[] data = await SendRequestAsync(httpClient, timestampAuthorityUri, content, maximumResponseSizeBytes, requireResponseContentType, cancellationToken).ConfigureAwait(false);
        Rfc3161TimestampToken token = request.ProcessResponse(data, out _);
        return new AsnEncodedData(OidConstants.MsCounterSign, token.AsSignedCms().Encode());
    }

    private static async Task<byte[]> SendRequestAsync(HttpClient client, Uri timestampAuthorityUri, ByteArrayContent content, int maximumResponseSizeBytes, bool requireResponseContentType, CancellationToken cancellationToken)
    {
        using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, timestampAuthorityUri) { Content = content };
        using HttpResponseMessage resp = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);

        if (!resp.IsSuccessStatusCode)
            throw new InvalidOperationException($"Timestamp authority returned an error: {resp.StatusCode}");

        string? mediaType = resp.Content.Headers.ContentType?.MediaType;
        if (mediaType == null)
        {
            if (requireResponseContentType)
                throw new InvalidOperationException("The timestamp authority response does not specify a Content-Type.");
        }
        else if (!string.Equals(mediaType, "application/timestamp-reply", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException($"The timestamp authority response has an invalid Content-Type: {mediaType}.");
        }

        if (resp.Content.Headers.ContentLength is long contentLength && contentLength > maximumResponseSizeBytes)
            throw new InvalidOperationException("The timestamp authority response exceeds the configured maximum size.");

        Stream stream = await resp.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        await using (stream.ConfigureAwait(false))
        {
            MemoryStream buffer = new MemoryStream(Math.Min(maximumResponseSizeBytes, 81920));
            await using (buffer.ConfigureAwait(false))
            {
                byte[] readBuffer = ArrayPool<byte>.Shared.Rent(81920);
                int totalRead = 0;
                try
                {
                    while (true)
                    {
                        int remaining = maximumResponseSizeBytes - totalRead;
                        if (remaining == 0)
                        {
                            if (await stream.ReadAsync(readBuffer.AsMemory(0, 1), cancellationToken).ConfigureAwait(false) != 0)
                                throw new InvalidOperationException("The timestamp authority response exceeds the configured maximum size.");
                            break;
                        }

                        int read = await stream.ReadAsync(readBuffer.AsMemory(0, Math.Min(readBuffer.Length, remaining)), cancellationToken).ConfigureAwait(false);
                        if (read == 0)
                            break;

                        totalRead += read;
                        await buffer.WriteAsync(readBuffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                    }

                    return buffer.ToArray();
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(readBuffer);
                }
            }
        }
    }
}