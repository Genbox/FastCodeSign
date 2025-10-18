using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Genbox.FastCodeSign.Internal.Native;
using Genbox.FastCodeSign.Internal.Native.Enums;
using Genbox.FastCodeSign.Internal.Native.Structs;
using Microsoft.Win32.SafeHandles;
using static Genbox.FastCodeSign.Internal.Native.Win32Native;

namespace Genbox.FastCodeSign.Native.Authenticode;

[SuppressMessage("Blocker Bug", "S3869:\"SafeHandle.DangerousGetHandle\" should not be called")]
public static class Authenticode
{
    private const int X509_ASN_ENCODING = 0x00000001;
    private static readonly Guid DRIVER_ACTION_VERIFY = new Guid("{F750E6C3-38EE-11d1-85E5-00C04FC295EE}");
    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new Guid("{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}");

    public static WinVerifyTrustResult VerifyFile(string fileName)
    {
        WINTRUST_FILE_INFO fileInfo = new WINTRUST_FILE_INFO(Path.GetFullPath(fileName));
        return WinVerifyCommon(fileInfo, WTD_CHOICE.WTD_CHOICE_FILE, WINTRUST_ACTION_GENERIC_VERIFY_V2, false);
    }

    public static WinVerifyTrustResult VerifyFileExt(string fileName, out string? signer, out byte[]? certificate)
    {
        WINTRUST_FILE_INFO fileInfo = new WINTRUST_FILE_INFO(Path.GetFullPath(fileName));
        return WinVerifyCommonExt(fileInfo, WTD_CHOICE.WTD_CHOICE_FILE, WINTRUST_ACTION_GENERIC_VERIFY_V2, false, out signer, out certificate);
    }

    public static WinVerifyTrustResult VerifyFileWithCab(string fileName, out byte[] hash)
    {
        WINTRUST_CATALOG_INFO catalogInfo = default;

        try
        {
            using FileStream stream = File.OpenRead(fileName);
            using SafeContextHandle contextHandle = GetContextHandle(HashAlgorithmName.SHA256);
            hash = GetPeHash(contextHandle, stream.SafeFileHandle);

            using SafeCatalogHandle catalog = GetCatalogFromHash(hash, contextHandle);

            if (catalog.IsInvalid)
                return WinVerifyTrustResult.TRUST_E_NOSIGNATURE;

            if (!CryptCATCatalogInfoFromContext(catalog, out CATALOG_INFO catInfo, 0))
                return WinVerifyTrustResult.TRUST_E_SYSTEM_ERROR;

            catalogInfo = new WINTRUST_CATALOG_INFO();
            catalogInfo.cbStruct = (uint)Marshal.SizeOf(catalogInfo);
            catalogInfo.pcwszCatalogFilePath = catInfo.wszCatalogFile;
            catalogInfo.pcwszMemberFilePath = fileName;
            catalogInfo.pcwszMemberTag = Convert.ToHexStringLower(hash);
            catalogInfo.cbCalculatedFileHash = (uint)hash.Length;
            catalogInfo.hCatAdmin = contextHandle.DangerousGetHandle();

            IntPtr hashPtr = Marshal.AllocHGlobal(hash.Length);
            Marshal.Copy(hash, 0, hashPtr, hash.Length);

            catalogInfo.pbCalculatedFileHash = hashPtr;

            return WinVerifyCommon(catalogInfo, WTD_CHOICE.WTD_CHOICE_CATALOG, DRIVER_ACTION_VERIFY, false);
        }
        finally
        {
            if (catalogInfo.pbCalculatedFileHash != IntPtr.Zero)
                Marshal.FreeHGlobal(catalogInfo.pbCalculatedFileHash);
        }
    }

    public static WinVerifyTrustResult VerifyFileWithCabExt(string fileName, out string? signer, out byte[]? certificate, out byte[]? hash)
    {
        signer = null;
        certificate = null;
        hash = null;

        WINTRUST_CATALOG_INFO catalogInfo = default;

        try
        {
            using FileStream stream = File.OpenRead(fileName);
            using SafeContextHandle contextHandle = GetContextHandle(HashAlgorithmName.SHA256);
            hash = GetPeHash(contextHandle, stream.SafeFileHandle);

            using SafeCatalogHandle catalog = GetCatalogFromHash(hash, contextHandle);

            if (catalog.IsInvalid)
                return WinVerifyTrustResult.TRUST_E_NOSIGNATURE;

            if (!CryptCATCatalogInfoFromContext(catalog, out CATALOG_INFO catInfo, 0))
                return WinVerifyTrustResult.TRUST_E_SYSTEM_ERROR;

            catalogInfo = new WINTRUST_CATALOG_INFO();
            catalogInfo.cbStruct = (uint)Marshal.SizeOf(catalogInfo);
            catalogInfo.pcwszCatalogFilePath = catInfo.wszCatalogFile;
            catalogInfo.pcwszMemberFilePath = fileName;
            catalogInfo.pcwszMemberTag = Convert.ToHexStringLower(hash);
            catalogInfo.cbCalculatedFileHash = (uint)hash.Length;
            catalogInfo.hCatAdmin = contextHandle.DangerousGetHandle();

            IntPtr hashPtr = Marshal.AllocHGlobal(hash.Length);
            Marshal.Copy(hash, 0, hashPtr, hash.Length);

            catalogInfo.pbCalculatedFileHash = hashPtr;

            return WinVerifyCommonExt(catalogInfo, WTD_CHOICE.WTD_CHOICE_CATALOG, DRIVER_ACTION_VERIFY, false, out signer, out certificate);
        }
        finally
        {
            if (catalogInfo.pbCalculatedFileHash != IntPtr.Zero)
                Marshal.FreeHGlobal(catalogInfo.pbCalculatedFileHash);
        }
    }

    public static byte[] GetPeHash(string fileName, HashAlgorithmName? hashAlgorithm = null)
    {
        if (hashAlgorithm != null && hashAlgorithm != HashAlgorithmName.SHA1 && !FunctionExists(Wintrust, nameof(CryptCATAdminCalcHashFromFileHandle2)))
            throw new NotSupportedException("Windows 7 and older does not support anything but SHA1.");

        using FileStream stream = File.OpenRead(fileName);

        using SafeContextHandle contextHandle = GetContextHandle(hashAlgorithm);
        return GetPeHash(contextHandle, stream.SafeFileHandle);
    }

    private static byte[] GetPeHash(SafeContextHandle contextHandle, SafeFileHandle fileHandle)
    {
        uint hashLength = 0;

        //We call the new version if available (it can switch hash type due to context)
        if (FunctionExists(Wintrust, nameof(CryptCATAdminCalcHashFromFileHandle2)))
        {
            //We call it with null to get the hash size
            CryptCATAdminCalcHashFromFileHandle2(contextHandle, fileHandle, ref hashLength, null, 0);
            byte[] hash = new byte[hashLength];

            if (CryptCATAdminCalcHashFromFileHandle2(contextHandle, fileHandle, ref hashLength, hash, 0))
                return hash;
        }
        else
        {
            CryptCATAdminCalcHashFromFileHandle(fileHandle, ref hashLength, null, 0);
            byte[] hash = new byte[hashLength];

            if (CryptCATAdminCalcHashFromFileHandle(fileHandle, ref hashLength, hash, 0))
                return hash;
        }

        throw new InvalidOperationException("Unable to hash file");
    }

    private static WinVerifyTrustResult WinVerifyCommon<T>(T data, WTD_CHOICE unionChoice, Guid action, bool enableRevocation) where T : struct
    {
        using WINTRUST_DATA trustData = new WINTRUST_DATA(unionChoice, enableRevocation, WTD_STATEACTION.WTD_STATEACTION_IGNORE, data);

        // -1: There is no interactive user. The trust provider performs the verification action without the user's assistance.
        //  0: The trust provider can use the interactive desktop to display its user interface.
        return WinVerifyTrust(new IntPtr(-1), action, in trustData);
    }

    private static WinVerifyTrustResult WinVerifyCommonExt<T>(T data, WTD_CHOICE unionChoice, Guid action, bool enableRevocation, out string? signer, out byte[]? certificate) where T : struct
    {
        WINTRUST_DATA trustData = new WINTRUST_DATA(unionChoice, enableRevocation, WTD_STATEACTION.WTD_STATEACTION_VERIFY, data);

        try
        {
            // -1: There is no interactive user. The trust provider performs the verification action without the user's assistance.
            //  0: The trust provider can use the interactive desktop to display its user interface.
            WinVerifyTrustResult res = WinVerifyTrust(new IntPtr(-1), action, in trustData);

            CERT_CONTEXT? context = GetSignerCertContext(trustData.hWVTStateData);

            if (context != null)
            {
                signer = GetSignerName(context.Value);
                certificate = new byte[context.Value.cbCertEncoded];
                Marshal.Copy(context.Value.pbCertEncoded, certificate, 0, certificate.Length);
            }
            else
            {
                signer = null;
                certificate = null;
            }

            return res;
        }
        finally
        {
            // Close the state data.
            trustData.dwStateAction = WTD_STATEACTION.WTD_STATEACTION_CLOSE;
            WinVerifyTrust(IntPtr.Zero, action, in trustData);

            trustData.Dispose();
        }
    }

    private static CERT_CONTEXT? GetSignerCertContext(IntPtr stateData)
    {
        if (stateData == IntPtr.Zero)
            return null;

        // 1. State data -> Provider data
        IntPtr provData = WTHelperProvDataFromStateData(stateData);

        if (provData == IntPtr.Zero)
            return null;

        // 2. Provider data -> Provider signer
        IntPtr signerInfo = WTHelperGetProvSignerFromChain(provData, 0, false, 0);

        if (signerInfo == IntPtr.Zero)
            return null;

        CRYPT_PROVIDER_SGNR sngr = Marshal.PtrToStructure<CRYPT_PROVIDER_SGNR>(signerInfo);

        if (sngr.pasCertChain == IntPtr.Zero)
            return null;

        if (sngr.csCertChain == 0)
            return null;

        // 3. Provider signer -> Provider cert
        CRYPT_PROVIDER_CERT cert = Marshal.PtrToStructure<CRYPT_PROVIDER_CERT>(sngr.pasCertChain);

        if (cert.pCert == IntPtr.Zero)
            return null;

        // 4. Provider cert -> Cert context
        CERT_CONTEXT context = Marshal.PtrToStructure<CERT_CONTEXT>(cert.pCert);

        if (context.pCertInfo == IntPtr.Zero)
            return null;

        return context;
    }

    private static string? GetSignerName(CERT_CONTEXT context)
    {
        // Cert context -> Cert info
        CERT_INFO certInfo = Marshal.PtrToStructure<CERT_INFO>(context.pCertInfo);

        // Ask for required char count (including the null terminator)
        int charCount = CertNameToStrW(X509_ASN_ENCODING, ref certInfo.Subject, CERT_NAME_STR.CERT_X500_NAME_STR, IntPtr.Zero, 0);

        if (charCount <= 0)
            return null;

        IntPtr buf = IntPtr.Zero;

        // Cert info subject -> Subject X.500 string
        try
        {
            buf = Marshal.AllocHGlobal(charCount * sizeof(char));

            int written = CertNameToStrW(X509_ASN_ENCODING, ref certInfo.Subject, CERT_NAME_STR.CERT_X500_NAME_STR, buf, (uint)charCount);

            if (written <= 0)
                return null;

            return Marshal.PtrToStringUni(buf);
        }
        finally
        {
            if (buf != IntPtr.Zero)
                Marshal.FreeHGlobal(buf);
        }
    }

    private static SafeCatalogHandle GetCatalogFromHash(byte[] hash, SafeContextHandle contextHandle)
    {
        SafeCatalogHandle retHandle = CryptCATAdminEnumCatalogFromHash(contextHandle, hash, (uint)hash.Length, 0, IntPtr.Zero);
        retHandle.ContextHandle = contextHandle;
        return retHandle;
    }

    private static SafeContextHandle GetContextHandle(HashAlgorithmName? hashAlgorithm)
    {
        //We try the newer variant first, as it has the ability to set the hash function
        if (FunctionExists(Wintrust, nameof(CryptCATAdminAcquireContext2)))
            if (CryptCATAdminAcquireContext2(out SafeContextHandle handle1, DRIVER_ACTION_VERIFY, hashAlgorithm?.Name, IntPtr.Zero, 0))
                return handle1;
            else
                throw new InvalidOperationException("Unable to obtain context");

        //We fall back to the older variant
        if (CryptCATAdminAcquireContext(out SafeContextHandle handle2, DRIVER_ACTION_VERIFY, 0))
            return handle2;

        throw new InvalidOperationException("Unable to obtain context");
    }

    private static bool FunctionExists(string dllName, string functionName)
    {
        IntPtr h = LoadLibraryW(dllName);
        if (h == IntPtr.Zero)
            return false;

        try
        {
            return GetProcAddress(h, functionName) != IntPtr.Zero;
        }
        finally
        {
            FreeLibrary(h);
        }
    }
}