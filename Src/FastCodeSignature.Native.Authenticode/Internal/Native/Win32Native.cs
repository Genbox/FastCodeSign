#nullable enable
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using Genbox.FastCodeSignature.Internal.Native.Enums;
using Genbox.FastCodeSignature.Internal.Native.Structs;
using Genbox.FastCodeSignature.Internal.Native.Win32;
using Genbox.FastCodeSignature.Native.Authenticode;
using Microsoft.Win32.SafeHandles;

namespace Genbox.FastCodeSignature.Internal.Native;

internal static partial class Win32Native
{
    private const string Kernel32 = "kernel32.dll";
    internal const string Wintrust = "wintrust.dll";
    private const string Crypt32 = "crypt32.dll";
    private const string Mssign32 = "mssign32.dll";

    [LibraryImport(Crypt32, StringMarshalling = StringMarshalling.Utf16)]
    internal static partial int CertNameToStrW(uint dwCertEncodingType, ref CRYPT_BLOB_ARRAY pName, CERT_NAME_STR dwStrType, IntPtr psz, uint csz);

    [LibraryImport(Wintrust,StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CryptCATCatalogInfoFromContext(SafeCatalogHandle hCatInfo, out CATALOG_INFO psCatInfo, int dwFlags);

    [LibraryImport(Wintrust,  StringMarshalling = StringMarshalling.Utf16)]
    internal static partial SafeCatalogHandle CryptCATAdminEnumCatalogFromHash(SafeContextHandle hCatAdmin, [In]byte[] pbHash, uint cbHash, int dwFlags, IntPtr phPrevCatInfo);

    [LibraryImport(Wintrust,StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CryptCATAdminAcquireContext(out SafeContextHandle phCatAdmin, in Guid pgSubsystem, int dwFlags);

    [LibraryImport(Wintrust,  StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CryptCATAdminAcquireContext2(out SafeContextHandle phCatAdmin, in Guid pgSubsystem, [MarshalAs(UnmanagedType.LPWStr)] string? pwszHashAlgorithm, IntPtr pStrongHashPolicy, uint dwFlags);

    [LibraryImport(Wintrust,  StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CryptCATAdminCalcHashFromFileHandle(SafeFileHandle hFile, ref uint pcbHash, [In]byte[]? pbHash, int dwFlags);

    [LibraryImport(Wintrust, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CryptCATAdminCalcHashFromFileHandle2(SafeContextHandle hCatAdmin, SafeFileHandle hFile, ref uint pcbHash, [In]byte[]? pbHash, int dwFlags);

    [LibraryImport(Wintrust, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, int dwFlags);

    [LibraryImport(Wintrust,StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CryptCATAdminReleaseCatalogContext(SafeContextHandle hCatAdmin, IntPtr hCatInfo, int dwFlags);

    [LibraryImport(Wintrust,  StringMarshalling = StringMarshalling.Utf16)]
    internal static partial WinVerifyTrustResult WinVerifyTrust(IntPtr hWnd, in Guid pgActionID, in WINTRUST_DATA pWVTData);

    [LibraryImport(Wintrust,  StringMarshalling = StringMarshalling.Utf16)]
    internal static partial IntPtr WTHelperGetProvSignerFromChain(IntPtr pProvData, int idxSigner, [MarshalAs(UnmanagedType.Bool)] bool fCounterSigner, int idxCounterSigner);

    [LibraryImport(Wintrust, StringMarshalling = StringMarshalling.Utf16)]
    internal static partial IntPtr WTHelperProvDataFromStateData(IntPtr hStateData);

    [LibraryImport(Kernel32, StringMarshalling = StringMarshalling.Utf16)]
    internal static partial IntPtr LoadLibraryW(string lpFileName);

    [LibraryImport(Kernel32, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr GetProcAddress(IntPtr hModule, string procName);

    [LibraryImport(Kernel32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool FreeLibrary(IntPtr hModule);

    [LibraryImport(Mssign32)]
    internal static unsafe partial int SignerSignEx3(
        SPCEx3 dwFlags,
        SIGNER_SUBJECT_INFO* pSubjectInfo,
        SIGNER_CERT* pSignerCert,
        SIGNER_SIGNATURE_INFO* pSignatureInfo,
        IntPtr pProviderInfo,
        SIGNER_TIMESTAMP dwTimestampFlags,
        byte* pszTimestampAlgorithmOid,
        char* pwszHttpTimeStamp,
        IntPtr psRequest,
        void* pSipData,
        IntPtr* ppSignerContext,
        IntPtr pCryptoPolicy,
        ref SIGNER_DIGEST_SIGN_INFO pSignInfo,
        IntPtr pReserved
    );
    
    [StructLayoutAttribute(LayoutKind.Sequential)]
    private struct SIGNER_CONTEXT
    {
        public uint cbSize;
        public uint cbBlob;
        public IntPtr pbBlob;
    }
    
    [DllImport("Mssign32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int SignerSignEx2(
        SPC_FLAGS  dwFlags,               // DWORD
        IntPtr pSubjectInfo,        // SIGNER_SUBJECT_INFO
        IntPtr pSignerCert,         // SIGNER_CERT
        IntPtr pSignatureInfo,      // SIGNER_SIGNATURE_INFO
        IntPtr pProviderInfo,       // SIGNER_PROVIDER_INFO
        uint  dwTimestampFlags,       // DWORD                  
        string? pszTimestampAlgOid,  // PCSTR
        string? pwszHttpTimeStamp,   // LPCWSTR
        IntPtr psRequest,           // PCRYPT_ATTRIBUTES
        IntPtr pSipData,            // LPVOID 
        out SIGNER_CONTEXT ppSignerContext,  // SIGNER_CONTEXT
        IntPtr PCSTR,               // PCERT_STRONG_SIGN_PARA 
        IntPtr pReserved            // PVOID                  
    );
    
    [LibraryImport(Mssign32)]
    internal static partial int SignerFreeSignerContext(IntPtr pSignerContext);

    [LibraryImport(Kernel32, SetLastError = true)]
    internal static partial IntPtr LocalAlloc(uint uFlags, UIntPtr uBytes);

    [LibraryImport(Kernel32, SetLastError = true)]
    internal static partial IntPtr LocalFree(IntPtr hMem);
}
