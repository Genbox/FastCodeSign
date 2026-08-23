using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Genbox.FastCodeSign.Handlers;
using Genbox.FastCodeSign.Models;

namespace Genbox.FastCodeSign.Tests;

public class TimestampTransportTests
{
    private const string NestedSignatureOid = "1.3.6.1.4.1.311.2.4.1";

    [Fact]
    private async Task ApplyTimestampAsync_RejectsUnexpectedResponseContentType()
    {
        using X509Certificate2 certificate = CreateCertificate();
        TimestampResponseHandler handler = new TimestampResponseHandler(Array.Empty<byte>(), "text/plain");
        using HttpClient client = new HttpClient(handler);
        CodeSignProvider provider = CreateProvider();

        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(() => provider.SignAsync(CreateOptions(certificate, client), cancellationToken: TestContext.Current.CancellationToken));

        Assert.Contains("Content-Type", exception.Message, StringComparison.Ordinal);
        Assert.Equal("application/timestamp-query", handler.RequestContentType);
    }

    [Fact]
    private async Task ApplyTimestampAsync_RejectsResponseLargerThanConfiguredLimit()
    {
        using X509Certificate2 certificate = CreateCertificate();
        TimestampResponseHandler handler = new TimestampResponseHandler(new byte[5], "application/timestamp-reply");
        using HttpClient client = new HttpClient(handler);
        CodeSignProvider provider = CreateProvider();
        SignOptions options = CreateOptions(certificate, client);
        options.Timestamp!.MaximumResponseSizeBytes = 4;

        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(() => provider.SignAsync(options, cancellationToken: TestContext.Current.CancellationToken));

        Assert.Contains("maximum size", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    private void VerifySignature_IncludesNestedAndConventionalCounterSigners()
    {
        using X509Certificate2 certificate = CreateCertificate();
        CodeSignProvider provider = CreateProvider();
        Signature signature = provider.CreateSignature(new SignOptions { Certificate = certificate });
        SignerInfo signer = signature.SignedCms.SignerInfos[0];

        SignedCms nested = new SignedCms();
        nested.Decode(signature.SignedCms.Encode());
        signer.AddUnsignedAttribute(new AsnEncodedData(NestedSignatureOid, nested.Encode()));
        signer.ComputeCounterSignature(new CmsSigner(certificate));
        provider.WriteSignature(signature);

        CodeSignVerificationResult result = provider.VerifySignature(new CodeSignVerificationOptions
        {
            TrustMode = X509ChainTrustMode.CustomRootTrust,
            CustomTrustRoots = [certificate],
            RevocationMode = X509RevocationMode.NoCheck,
            ApplicationPolicyOids = []
        });

        Assert.Equal(SignatureIntegrityStatus.Valid, result.IntegrityStatus);
        Assert.Equal(3, result.Signers.Count);
    }

    [Fact]
    private void VerifySignature_RejectsMalformedNestedCms()
    {
        using X509Certificate2 certificate = CreateCertificate();
        CodeSignProvider provider = CreateProvider();
        Signature signature = provider.CreateSignature(new SignOptions { Certificate = certificate });
        signature.SignedCms.SignerInfos[0].AddUnsignedAttribute(new AsnEncodedData(NestedSignatureOid, [0x01, 0x01, 0xff]));
        provider.WriteSignature(signature);

        CodeSignVerificationResult result = provider.VerifySignature();

        Assert.Equal(SignatureIntegrityStatus.Invalid, result.IntegrityStatus);
    }

    private static CodeSignProvider CreateProvider() => CodeSignProvider.FromData(Encoding.UTF8.GetBytes("Write-Output 'timestamp transport test'\r\n"), new PowerShellScriptFormatHandler(Encoding.UTF8));

    private static SignOptions CreateOptions(X509Certificate2 certificate, HttpClient client) => new SignOptions
    {
        Certificate = certificate,
        Timestamp = new TimestampOptions
        {
            TimestampAuthorityUri = new Uri("https://timestamp.example.test"),
            HttpClient = client
        }
    };

    private static X509Certificate2 CreateCertificate()
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest request = new CertificateRequest("CN=Timestamp Transport Test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }

    private sealed class TimestampResponseHandler(byte[] response, string contentType) : HttpMessageHandler
    {
        internal string? RequestContentType { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            RequestContentType = request.Content?.Headers.ContentType?.MediaType;
            ByteArrayContent content = new ByteArrayContent(response);
            content.Headers.ContentType = new MediaTypeHeaderValue(contentType);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = content });
        }
    }
}