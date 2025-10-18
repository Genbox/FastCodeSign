using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Genbox.FastCodeSign.Native.Authenticode.Internal;
using Genbox.FastCodeSign.Native.Authenticode.Internal.Enums;
using Genbox.FastCodeSign.Internal.Native;
using Genbox.FastCodeSign.Internal.Native.Enums;
using Genbox.FastCodeSign.Internal.Native.Structs;
using Genbox.FastCodeSign.Internal.Native.Unions;

namespace Genbox.FastCodeSign.Native.Authenticode;

public static class AuthenticodeSigner
{
    private const uint E_INVALIDARG = 0x80070057;
    private static readonly SignCallback _signCallback = SignCallback; //Need this rooted so the GC does not collect it

    public static unsafe void SignFile(string path, X509Certificate2 signingCertificate, AsymmetricAlgorithm signingAlgorithm, HashAlgorithmName fileDigestAlgorithm, TimeStampConfiguration? timeStampConfig)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException(path);

        SPCEx3 flags = SPCEx3.SIGN_CALLBACK_UNDOCUMENTED;

        SIGNER_TIMESTAMP timeStampFlags = default;
        ReadOnlySpan<byte> timestampAlgorithmOid = null;
        string? timestampUrl = null;

        if (timeStampConfig != null)
        {
            switch (timeStampConfig.Type)
            {
                case TimeStampType.Authenticode:
                    timeStampFlags = SIGNER_TIMESTAMP.SIGNER_TIMESTAMP_AUTHENTICODE;
                    timestampAlgorithmOid = default;
                    timestampUrl = timeStampConfig.Url;
                    break;
                case TimeStampType.Rfc3161:
                    timeStampFlags = SIGNER_TIMESTAMP.SIGNER_TIMESTAMP_RFC3161;
                    timestampAlgorithmOid = OidHelper.HashAlgorithmToOidAsciiTerminated(timeStampConfig.DigestAlgorithm);
                    timestampUrl = timeStampConfig.Url;
                    break;
                default:
                    throw new InvalidOperationException("Invalid timestamp type.");
            }
        }

        int pathLength = path.Length + 1;
        Span<char> pathBuf = pathLength <= 512 ? stackalloc char[pathLength] : new char[pathLength];
        path.AsSpan().CopyTo(pathBuf);
        pathBuf[^1] = '\0';

        fixed (char* pTimestampUrl = timestampUrl)
        fixed (char* pPath = pathBuf)
        fixed (byte* pTimestampAlgorithmOid = timestampAlgorithmOid)
        {
            SIGNER_FILE_INFO fileInfo = new SIGNER_FILE_INFO(pPath, 0);
            uint subjectIndex = 0u;
            SIGNER_SUBJECT_INFO_UNION signerSubjectInfoUnion = new SIGNER_SUBJECT_INFO_UNION(&fileInfo);
            SIGNER_SUBJECT_INFO subjectInfo = new SIGNER_SUBJECT_INFO(&subjectIndex, SIGNER_SUBJECT.SIGNER_SUBJECT_FILE, signerSubjectInfoUnion);

            SIGNER_CERT_STORE_INFO storeInfo = new SIGNER_CERT_STORE_INFO(signingCertificate.Handle, SIGNER_CERT_POLICY.SIGNER_CERT_POLICY_CHAIN, IntPtr.Zero);
            SIGNER_CERT signerCert = new SIGNER_CERT(SIGNER_CERT_CHOICE.SIGNER_CERT_STORE, new SIGNER_CERT_UNION(&storeInfo));

            SIGNER_ATTR_AUTHCODE authCodeStructure = new SIGNER_ATTR_AUTHCODE();
            SIGNER_SIGNATURE_INFO signatureInfo = new SIGNER_SIGNATURE_INFO(OidHelper.HashAlgorithmToAlgId(fileDigestAlgorithm), SIGNER.SIGNER_AUTHCODE_ATTR, new SIGNER_SIGNATURE_INFO_UNION(&authCodeStructure));

            IntPtr context = IntPtr.Zero;

            IntPtr callbackPtr = Marshal.GetFunctionPointerForDelegate(_signCallback);
            SignContext ctx = new SignContext(signingAlgorithm, fileDigestAlgorithm);
            GCHandle gch = GCHandle.Alloc(ctx, GCHandleType.Normal);
            SIGNER_DIGEST_SIGN_INFO signCallbackInfo = new SIGNER_DIGEST_SIGN_INFO(callbackPtr, (IntPtr)gch);

            SipKind sipKind = GetSipKind(path);
            void* sipData = null;

            try
            {
                if (sipKind == SipKind.Appx)
                {
                    flags &= ~SPCEx3.SPC_INC_PE_PAGE_HASHES_FLAG;
                    flags |= SPCEx3.SPC_EXC_PE_PAGE_HASHES_FLAG;

                    SIGNER_SIGN_EX3_PARAMS parameters = new SIGNER_SIGN_EX3_PARAMS(flags, timeStampFlags, &subjectInfo, &signerCert, &signatureInfo, &context, pTimestampUrl, pTimestampAlgorithmOid, &signCallbackInfo);
                    APPX_SIP_CLIENT_DATA cd = new APPX_SIP_CLIENT_DATA(&parameters);
                    sipData = &cd;
                }

                int result = Win32Native.SignerSignEx3(flags, &subjectInfo, &signerCert, &signatureInfo, IntPtr.Zero, timeStampFlags, pTimestampAlgorithmOid, pTimestampUrl, IntPtr.Zero, sipData, &context, IntPtr.Zero, ref signCallbackInfo, IntPtr.Zero);

                if (result != 0)
                    throw new InvalidOperationException($"Signing failed with code {Marshal.GetPInvokeErrorMessage(result)}");

                if (context != IntPtr.Zero)
                    if (Win32Native.SignerFreeSignerContext(context) != 0)
                        throw new InvalidOperationException("Error happened while freeing signer context");

                if (sipKind == SipKind.Appx)
                {
                    IntPtr state = ((APPX_SIP_CLIENT_DATA*)sipData)->pAppxSipState;
                    if (state != IntPtr.Zero)
                        Marshal.Release(state); //State is an IUnknown COM interface pointer
                }
            }
            finally
            {
                if (gch.IsAllocated)
                    gch.Free();
            }
        }
    }

    private static SipKind GetSipKind(ReadOnlySpan<char> filePath)
    {
        string extension = Path.GetExtension(filePath.ToString());
        if (extension.Equals(".appx", StringComparison.OrdinalIgnoreCase) || extension.Equals(".eappx", StringComparison.OrdinalIgnoreCase) || extension.Equals(".appxbundle", StringComparison.OrdinalIgnoreCase) || extension.Equals(".eappxbundle", StringComparison.OrdinalIgnoreCase) || extension.Equals(".msix", StringComparison.OrdinalIgnoreCase) || extension.Equals(".emsix", StringComparison.OrdinalIgnoreCase) || extension.Equals(".msixbundle", StringComparison.OrdinalIgnoreCase) || extension.Equals(".emsixbundle", StringComparison.OrdinalIgnoreCase))
            return SipKind.Appx;

        return SipKind.None;
    }

    private static uint SignCallback(IntPtr pCertContext, IntPtr pvExtra, uint algId, byte[] pDigestToSign, uint dwDigestToSign, ref CRYPT_BLOB_ARRAY blob)
    {
        GCHandle handle = GCHandle.FromIntPtr(pvExtra);
        SignContext ctx = (SignContext)handle.Target!;

        byte[] signature;
        switch (ctx.SigningAlgorithm)
        {
            case RSA rsa:
                signature = rsa.SignHash(pDigestToSign, ctx.FileDigestAlgorithm, RSASignaturePadding.Pkcs1);
                break;
            case ECDsa ecdsa:
                signature = ecdsa.SignHash(pDigestToSign);
                break;
            default:
                return E_INVALIDARG;
        }

        // Allocate unmanaged buffer with LocalAlloc so SignerSignEx3 can free it
        IntPtr resultPtr = Win32Native.LocalAlloc(0 /* LMEM_FIXED */, (UIntPtr)signature.Length);

        if (resultPtr == IntPtr.Zero)
            return (uint)Marshal.GetLastWin32Error();

        Marshal.Copy(signature, 0, resultPtr, signature.Length);

        blob.pbData = resultPtr;
        blob.cbData = (uint)signature.Length;
        return 0;
    }

    private sealed class SignContext(AsymmetricAlgorithm alg, HashAlgorithmName digest)
    {
        public AsymmetricAlgorithm SigningAlgorithm { get; } = alg;
        public HashAlgorithmName FileDigestAlgorithm { get; } = digest;
    }
}