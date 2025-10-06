using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Genbox.FastCodeSignature.Internal;
using Genbox.FastCodeSignature.Internal.Helpers;

namespace Genbox.FastCodeSignature.Extensions;

public static class SignedCmsExtensions
{
    /// <summary>
    /// Returns a list of RFC3161 counter-signatures on a signed CMS.
    /// </summary>
    /// <returns>A list of counter-signatures</returns>
    /// <exception cref="InvalidOperationException">If the file contains invalid counter-signatures</exception>
    public static IEnumerable<CounterSignature> GetCounterSignatures(this SignedCms signedCms)
    {
        // There are no signer infos at all, so there are no counter-signatures
        if (signedCms.SignerInfos.Count == 0)
            yield break;

        // RFC3161 (Time-Stamp Protocol)
        foreach (SignerInfo attr in signedCms.SignerInfos)
        {
            foreach (CounterSignature signature in attr.GetCounterSignatures())
                yield return signature;
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