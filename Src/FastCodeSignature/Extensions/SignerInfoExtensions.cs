using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Genbox.FastCodeSignature.Internal;
using Genbox.FastCodeSignature.Internal.Helpers;

namespace Genbox.FastCodeSignature.Extensions;

public static class SignerInfoExtensions
{
    /// <summary>
    /// Returns a list of RFC3161 counter-signatures
    /// </summary>
    /// <returns>A list of counter-signatures</returns>
    /// <exception cref="InvalidOperationException">If the file contains invalid counter-signatures</exception>
    public static IEnumerable<CounterSignature> GetCounterSignatures(this SignerInfo signerInfo)
    {
        // RFC3161 (Time-Stamp Protocol)
        foreach (CryptographicAttributeObject attr in signerInfo.UnsignedAttributes)
        {
            if (attr.Oid.Value != OidConstants.MsCounterSign)
                continue;

            if (!Rfc3161TimestampToken.TryDecode(attr.Values[0].RawData, out Rfc3161TimestampToken? token, out _))
                throw new InvalidOperationException("The counter signature does not contain a valid token.");

            SignedCms cms = token.AsSignedCms();

            if (cms.SignerInfos.Count == 0)
                throw new InvalidOperationException("The counter signature does not contain any signer infos.");

            X509Certificate2? cert = cms.SignerInfos[0].Certificate;
            if (cert == null)
                throw new InvalidOperationException("The counter signature does not contain a certificate.");

            Rfc3161TimestampTokenInfo info = token.TokenInfo;
            yield return new CounterSignature(cert, OidHelper.OidToHashAlgorithm(info.HashAlgorithmId.Value), info.Timestamp.UtcDateTime);
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
    /// <param name="url">The url of the timestamp server</param>
    /// <param name="hashAlgorithm">The hashing algorithm to use</param>
    public static async Task CounterSignAsync(this SignerInfo signerInfo, string url, HashAlgorithmName hashAlgorithm)
    {
        using RandomNumberGenerator rng = RandomNumberGenerator.Create();
        byte[] nonce = new byte[8];
        rng.GetBytes(nonce);

        Rfc3161TimestampRequest request = Rfc3161TimestampRequest.CreateFromSignerInfo(signerInfo, hashAlgorithm, null, nonce, true);

        using HttpClient client = new HttpClient();
        using ByteArrayContent content = new ByteArrayContent(request.Encode());
        content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-query");

        byte[] data = await SendRequestAsync(client, url, content).ConfigureAwait(false);

        Rfc3161TimestampToken token = request.ProcessResponse(data, out _);
        signerInfo.AddUnsignedAttribute(new AsnEncodedData(OidConstants.MsCounterSign, token.AsSignedCms().Encode()));
    }

    private static async Task<byte[]> SendRequestAsync(HttpClient client, string url, ByteArrayContent content)
    {
        using HttpResponseMessage resp = await client.PostAsync(url, content).ConfigureAwait(false);

        if (!resp.IsSuccessStatusCode)
            throw new InvalidOperationException($"Timestamp authority return an error: {resp.StatusCode}");

        return await resp.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
    }
}