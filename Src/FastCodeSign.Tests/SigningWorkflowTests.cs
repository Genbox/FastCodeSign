using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Genbox.FastCodeSign.Allocations;
using Genbox.FastCodeSign.Enums;
using Genbox.FastCodeSign.Handlers;
using Genbox.FastCodeSign.Helpers;
using Genbox.FastCodeSign.Internal.MachObject;
using Genbox.FastCodeSign.Internal.MachObject.Headers.Enums;
using Genbox.FastCodeSign.MachObjects;
using Genbox.FastCodeSign.Models;
using Genbox.FastCodeSign.Tests.Code;
using MachObjectModel = Genbox.FastCodeSign.Models.MachObject;

namespace Genbox.FastCodeSign.Tests;

public class SigningWorkflowTests
{
    [Fact]
    private async Task UniversalMachO_SignsVerifiesAndRemovesAllSlices()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        byte[] thin = await File.ReadAllBytesAsync(Path.Combine(Constants.FilesDir, "Unsigned/MachO/macho_unsigned.dat"), cancellationToken);
        MemoryAllocation allocation = new MemoryAllocation(CreateUniversalMachO(thin));
        CodeSignProvider provider = CodeSignProvider.FromAllocation(allocation);

        CodeSignVerificationResult unsignedResult = provider.VerifySignature();
        Assert.Equal(SignatureIntegrityStatus.NotSigned, unsignedResult.IntegrityStatus);

        using X509Certificate2 certificate = Constants.GetCert();
        await provider.SignAsync(new SignOptions { Certificate = certificate }, new MachObjectFormatOptions
        {
            Identifier = "com.fastcodesign.universal-test",
            SigningFlags = MachObjectSigningFlags.HardenedRuntime
        }, cancellationToken);

        Assert.Equal(2, provider.GetSignatures().Count);
        Assert.All(provider.GetSignatures(), signature => Assert.True(provider.HasValidSignature(signature)));

        ReadOnlySpan<byte> signedData = allocation.GetSpan();

        foreach (MachObjectModel machObject in MachObjectHelper.GetMachObjects(signedData))
        {
            ReadOnlySpan<byte> slice = machObject.GetSpan(signedData);
            MachOContext context = MachOContext.Create(slice);
            Assert.True(MachObjectFormatHandler.TryExtractSpecialSlot(context, slice, CsSlot.CodeDirectory, out ReadOnlySpan<byte> codeDirectory));
            Assert.True(((CdFlags)BinaryPrimitives.ReadUInt32BigEndian(codeDirectory[12..])).HasFlag(CdFlags.Runtime));
        }

        CodeSignVerificationResult verification = provider.VerifySignature(new CodeSignVerificationOptions
        {
            TrustMode = X509ChainTrustMode.CustomRootTrust,
            CustomTrustRoots = [certificate],
            RevocationMode = X509RevocationMode.NoCheck,
            VerificationTime = certificate.NotBefore.AddDays(1)
        });
        Assert.True(verification.IntegrityStatus == SignatureIntegrityStatus.Valid, verification.Diagnostic);
        Assert.Equal(CertificateTrustStatus.Trusted, verification.TrustStatus);
        Assert.Equal(2, verification.Signers.Count);
        Assert.True(verification.Success);

        Assert.True(provider.TryRemoveSignature(true));
        Assert.False(provider.HasSignature());
        Assert.Equal(2, MachObjectHelper.GetMachObjects(allocation.GetSpan()).Length);
    }

    [Fact]
    private async Task TimestampFailure_DoesNotReplaceExistingSignature()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        byte[] unsigned = await File.ReadAllBytesAsync(Path.Combine(Constants.FilesDir, "Unsigned/PowerShell/ps1_unsigned.dat"), cancellationToken);
        MemoryAllocation allocation = new MemoryAllocation(unsigned);
        CodeSignProvider provider = CodeSignProvider.FromAllocation(allocation, new PowerShellScriptFormatHandler(Encoding.UTF8));

        using X509Certificate2 certificate = Constants.GetCert();
        await provider.SignAsync(new SignOptions { Certificate = certificate }, cancellationToken: cancellationToken);
        byte[] originalSignature = allocation.GetSpan().ToArray();

        await Assert.ThrowsAsync<InvalidOperationException>(() => provider.SignAsync(new SignOptions { Certificate = certificate }, cancellationToken: cancellationToken));
        Assert.Equal(originalSignature, allocation.GetSpan().ToArray());

        ErrorTimestampHandler handler = new ErrorTimestampHandler();
        using HttpClient client = new HttpClient(handler);
        SignOptions replacement = new SignOptions
        {
            Certificate = certificate,
            ExistingSignatureBehavior = ExistingSignatureBehavior.Replace,
            Timestamp = new TimestampOptions
            {
                TimestampAuthorityUri = new Uri("https://timestamp.example.test"),
                HttpClient = client
            }
        };

        await Assert.ThrowsAsync<InvalidOperationException>(() => provider.SignAsync(replacement, cancellationToken: cancellationToken));
        Assert.Equal(originalSignature, allocation.GetSpan().ToArray());
        Assert.True(provider.HasValidSignature(provider.GetSignature()!));
        Assert.Equal(1, handler.RequestCount);
        Assert.Equal("application/timestamp-query", handler.ContentType);
    }

    private static byte[] CreateUniversalMachO(byte[] slice)
    {
        const int alignment = 4096;
        int firstOffset = alignment;
        int secondOffset = ((firstOffset + slice.Length + alignment) - 1) & ~(alignment - 1);
        byte[] result = new byte[secondOffset + slice.Length];

        BinaryPrimitives.WriteUInt32BigEndian(result, 0xcafe_babe);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(4), 2);
        MachObjectModel source = MachObjectHelper.GetMachObjects(slice)[0];
        uint cpuType = (uint)source.CpuType;
        uint cpuSubType = Convert.ToUInt32(source.CpuSubType, CultureInfo.InvariantCulture);
        WriteArchitecture(result.AsSpan(8), cpuType, cpuSubType, firstOffset, slice.Length);
        WriteArchitecture(result.AsSpan(28), cpuType, cpuSubType, secondOffset, slice.Length);
        slice.CopyTo(result.AsSpan(firstOffset));
        slice.CopyTo(result.AsSpan(secondOffset));
        return result;
    }

    private static void WriteArchitecture(Span<byte> destination, uint cpuType, uint cpuSubType, int offset, int size)
    {
        BinaryPrimitives.WriteUInt32BigEndian(destination, cpuType);
        BinaryPrimitives.WriteUInt32BigEndian(destination[4..], cpuSubType);
        BinaryPrimitives.WriteUInt32BigEndian(destination[8..], (uint)offset);
        BinaryPrimitives.WriteUInt32BigEndian(destination[12..], (uint)size);
        BinaryPrimitives.WriteUInt32BigEndian(destination[16..], 12);
    }

    private sealed class ErrorTimestampHandler : HttpMessageHandler
    {
        public int RequestCount { get; private set; }
        public string? ContentType { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            RequestCount++;
            ContentType = request.Content?.Headers.ContentType?.MediaType;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.InternalServerError));
        }
    }
}