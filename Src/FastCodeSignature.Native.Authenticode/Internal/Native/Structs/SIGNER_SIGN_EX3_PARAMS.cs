using System.Runtime.InteropServices;
using Genbox.FastCodeSignature.Internal.Native.Enums;

namespace Genbox.FastCodeSignature.Internal.Native.Structs;

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct SIGNER_SIGN_EX3_PARAMS
{
    public SPCEx3 dwFlags;
    public SIGNER_SUBJECT_INFO* pSubjectInfo;
    public SIGNER_CERT* pSignerCert;
    public SIGNER_SIGNATURE_INFO* pSignatureInfo;
    public IntPtr pProviderInfo;
    public SIGNER_TIMESTAMP dwTimestampFlags;
    public byte* pszTimestampAlgorithmOid;
    public char* pwszHttpTimeStamp;
    public IntPtr psRequest;
    public SIGNER_DIGEST_SIGN_INFO* pSignCallBack;
    public IntPtr* ppSignerContext;
    public IntPtr pCryptoPolicy;
    public IntPtr pReserved;

    public SIGNER_SIGN_EX3_PARAMS(SPCEx3 dwFlags, SIGNER_TIMESTAMP dwTimestampFlags, SIGNER_SUBJECT_INFO* pSubjectInfo, SIGNER_CERT* pSignerCert, SIGNER_SIGNATURE_INFO* pSignatureInfo, IntPtr* ppSignerContext, char* pwszHttpTimeStamp, byte* pszTimestampAlgorithmOid, SIGNER_DIGEST_SIGN_INFO* pSignCallBack) : this()
    {
        this.dwFlags = dwFlags;
        this.dwTimestampFlags = dwTimestampFlags;
        this.pSubjectInfo = pSubjectInfo;
        this.pSignerCert = pSignerCert;
        this.pSignatureInfo = pSignatureInfo;
        this.ppSignerContext = ppSignerContext;
        this.pwszHttpTimeStamp = pwszHttpTimeStamp;
        this.pszTimestampAlgorithmOid = pszTimestampAlgorithmOid;
        this.pSignCallBack = pSignCallBack;
    }
}