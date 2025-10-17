using System.Security.Cryptography.Pkcs;
using Genbox.FastCodeSignature.Models;

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
        foreach (SignerInfo info in signedCms.SignerInfos)
        {
            foreach (CounterSignature signature in info.GetCounterSignatures())
                yield return signature;
        }
    }

    /// <summary>Extracts nested signatures from all SignerInfos in the SignedCms</summary>
    /// <returns>Nested signatures</returns>
    public static IEnumerable<SignedCms> GetNestedSignatures(this SignedCms signedCms)
    {
        if (signedCms.SignerInfos.Count == 0)
            yield break;

        foreach (var signerInfo in signedCms.SignerInfos)
        {
            foreach (SignedCms sig in signerInfo.GetNestedSignatures())
                yield return sig;
        }
    }
}