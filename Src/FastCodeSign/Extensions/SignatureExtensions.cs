using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using Genbox.FastCodeSign.Models;

namespace Genbox.FastCodeSign.Extensions;

public static class SignatureExtensions
{
    /// <summary>Applies an RFC3161 timestamp to every signer in a signature.</summary>
    public static async Task ApplyTimestampAsync(this Signature signature, TimestampOptions timestampOptions, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(timestampOptions);
        await ApplyTimestampAsync(signature.SignedCmsSignatures.SelectMany(static signedCms => signedCms.SignerInfos.Cast<SignerInfo>()), timestampOptions, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Applies an RFC3161 timestamp to every signer in a bundle signature.</summary>
    public static async Task ApplyTimestampAsync(this BundleSignature signature, TimestampOptions timestampOptions, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(timestampOptions);

        await ApplyTimestampAsync(signature.Signatures.SelectMany(static item => item.SignedCmsSignatures).SelectMany(static signedCms => signedCms.SignerInfos.Cast<SignerInfo>()), timestampOptions, cancellationToken).ConfigureAwait(false);
    }

    private static async Task ApplyTimestampAsync(IEnumerable<SignerInfo> signerInfos, TimestampOptions timestampOptions, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(timestampOptions.TimestampAuthorityUri, nameof(timestampOptions));
        ValidateTimeout(timestampOptions.Timeout);
        ValidateMaximumResponseSize(timestampOptions.MaximumResponseSizeBytes);
        cancellationToken.ThrowIfCancellationRequested();

        HttpClient? configuredClient = timestampOptions.HttpClient;
        HttpClient client = configuredClient ?? new HttpClient();
        HttpClient? ownedClient = configuredClient == null ? client : null;
        try
        {
            List<(SignerInfo SignerInfo, AsnEncodedData Attribute)> attributes = new List<(SignerInfo, AsnEncodedData)>();
            foreach (SignerInfo signerInfo in signerInfos)
                attributes.Add((signerInfo, await GetTimestampAttributeAsync(signerInfo, timestampOptions, client, cancellationToken).ConfigureAwait(false)));

            cancellationToken.ThrowIfCancellationRequested();
            foreach ((SignerInfo signerInfo, AsnEncodedData attribute) in attributes)
                signerInfo.AddUnsignedAttribute(attribute);
        }
        finally
        {
            ownedClient?.Dispose();
        }
    }

    private static Task<AsnEncodedData> GetTimestampAttributeAsync(SignerInfo signerInfo, TimestampOptions timestampOptions, HttpClient client, CancellationToken cancellationToken)
    {
        if (timestampOptions.Timeout is not TimeSpan timeout)
            return signerInfo.GetTimestampAttributeAsync(timestampOptions.TimestampAuthorityUri, timestampOptions.HashAlgorithm, client, timestampOptions.MaximumResponseSizeBytes, timestampOptions.RequireResponseContentType, cancellationToken);

        return GetTimestampAttributeWithTimeoutAsync(signerInfo, timestampOptions.TimestampAuthorityUri, timestampOptions.HashAlgorithm, client, timestampOptions.MaximumResponseSizeBytes, timestampOptions.RequireResponseContentType, timeout, cancellationToken);
    }

    private static async Task<AsnEncodedData> GetTimestampAttributeWithTimeoutAsync(SignerInfo signerInfo, Uri timestampAuthorityUri, System.Security.Cryptography.HashAlgorithmName hashAlgorithm, HttpClient client, int maximumResponseSizeBytes, bool requireResponseContentType, TimeSpan timeout, CancellationToken cancellationToken)
    {
        using CancellationTokenSource timeoutCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCancellation.CancelAfter(timeout);
        return await signerInfo.GetTimestampAttributeAsync(timestampAuthorityUri, hashAlgorithm, client, maximumResponseSizeBytes, requireResponseContentType, timeoutCancellation.Token).ConfigureAwait(false);
    }

    private static void ValidateTimeout(TimeSpan? timeout)
    {
        if (timeout is not TimeSpan value)
            return;

        if (value < TimeSpan.Zero || value > TimeSpan.FromMilliseconds(uint.MaxValue - 1))
            throw new ArgumentOutOfRangeException(nameof(timeout), "Timeout must be non-negative and no greater than the maximum supported cancellation timeout.");
    }

    private static void ValidateMaximumResponseSize(int maximumResponseSizeBytes)
    {
        if (maximumResponseSizeBytes <= 0)
            throw new ArgumentOutOfRangeException(nameof(maximumResponseSizeBytes), "The maximum response size must be positive.");
    }
}