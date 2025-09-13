using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using Genbox.FastCodeSignature.Internal;

namespace Genbox.FastCodeSignature.Extensions;

public static class SignerInfoExtensions
{
    /// <summary>
    /// Countersign a SignerInfo using PKCS#9
    /// </summary>
    /// <param name="signerInfo">The signer info</param>
    public static void Pkcs9CounterSign(this SignerInfo signerInfo)
    {
        signerInfo.SignedAttributes.Add(new Pkcs9SigningTime());
    }

    /// <summary>
    /// Countersign a SignerInfo using RFC3161.
    /// </summary>
    /// <param name="signerInfo">The signer info</param>
    /// <param name="url">The url of the timestamp server</param>
    /// <param name="hashAlgorithm">The hashing algorithm to use</param>
    public static async Task Rfc3161CounterSignAsync(this SignerInfo signerInfo, string url, HashAlgorithmName hashAlgorithm)
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