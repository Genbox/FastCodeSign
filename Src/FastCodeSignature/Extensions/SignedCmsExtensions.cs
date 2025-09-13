using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Genbox.FastCodeSignature.Internal;
using Genbox.FastCodeSignature.Internal.Helpers;

namespace Genbox.FastCodeSignature.Extensions;

public static class SignedCmsExtensions
{
    /// <summary>
    /// Returns a list of counter signatures on a signed CMS. It supports both PKCS#9 and RFC3161 signatures
    /// </summary>
    /// <returns>A list of counter signatures</returns>
    /// <exception cref="InvalidOperationException">If the file contains invalid counter signatures</exception>
    public static IEnumerable<CounterSignature> GetCounterSignatures(this SignedCms signedCms)
    {
        // There are no signer infos at all, so there are no counter signatures
        if (signedCms.SignerInfos.Count == 0)
            yield break;

        // The counter signature should always be the first signer info.
        SignerInfo signInfo = signedCms.SignerInfos[0];

        // PKCS#9 counter-signatures (SigningTime)
        foreach (SignerInfo counterSigner in signInfo.CounterSignerInfos)
        {
            X509Certificate2? cert = counterSigner.Certificate;

            if (cert == null)
                continue;

            DateTime? timeStamp = null;
            foreach (CryptographicAttributeObject attr in counterSigner.SignedAttributes)
            {
                if (attr.Oid.Value == OidConstants.SigningTime && attr.Values[0] is Pkcs9SigningTime st)
                {
                    timeStamp = st.SigningTime.ToUniversalTime();
                    break;
                }
            }

            if (timeStamp == null)
                throw new InvalidOperationException("Expected a timestamp, but was unable to find one.");

            yield return new CounterSignature(cert, OidHelper.OidToHashAlgorithm(counterSigner.DigestAlgorithm.Value ?? ""), timeStamp.Value);
        }

        // RFC3161 (Time-Stamp Protocol)
        foreach (CryptographicAttributeObject attr in signInfo.UnsignedAttributes)
        {
            if (attr.Oid.Value != OidConstants.MsCounterSign) continue;

            if (!Rfc3161TimestampToken.TryDecode(attr.Values[0].RawData, out Rfc3161TimestampToken? token, out _))
                throw new InvalidOperationException("The counter signature does not contain a valid token.");

            SignedCms cms = token.AsSignedCms();

            if (cms.SignerInfos.Count <= 1)
                throw new InvalidOperationException("The counter signature does not contain any signer infos.");

            X509Certificate2? cert = cms.SignerInfos[0].Certificate;
            if (cert == null)
                throw new InvalidOperationException("The counter signature does not contain a certificate.");

            Rfc3161TimestampTokenInfo info = token.TokenInfo;
            yield return new CounterSignature(cert, OidHelper.OidToHashAlgorithm(info.HashAlgorithmId.Value), info.Timestamp.UtcDateTime);
        }
    }

    /// <summary>
    /// Microsoft supports nested signatures. This method is able to extract nested signatures.
    /// </summary>
    /// <returns>Nested signatures</returns>
    public static IEnumerable<SignedCms> GetNestedSignatures(this SignedCms signedCms)
    {
        if (signedCms.SignerInfos.Count == 0)
            yield break;

        foreach (CryptographicAttributeObject attr in signedCms.SignerInfos[0].UnsignedAttributes)
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
}