using System.Runtime.InteropServices;
using Genbox.FastCodeSign.Internal.Native.Enums;

namespace Genbox.FastCodeSign.Internal.Native.Structs;

//https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data
[StructLayout(LayoutKind.Sequential)]
internal struct WINTRUST_DATA : IDisposable
{
    internal WINTRUST_DATA(WTD_CHOICE choice, bool enableRevocation, WTD_STATEACTION stateAction, object data)
    {
        dwUnionChoice = choice;

        UnionData = Marshal.AllocHGlobal(Marshal.SizeOf(data));
        Marshal.StructureToPtr(data, UnionData, false);

        if (enableRevocation)
        {
            dwProvFlags = WTD.WTD_REVOCATION_CHECK_CHAIN;
            fdwRevocationChecks = WTD_REVOKE.WTD_REVOKE_WHOLECHAIN;
        }
        else
        {
            dwProvFlags |= WTD.WTD_REVOCATION_CHECK_NONE;
            fdwRevocationChecks = WTD_REVOKE.WTD_REVOKE_NONE;
        }

        dwStateAction = stateAction;
    }

    internal uint cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(); // The size, in bytes, of this structure.
    internal IntPtr pPolicyCallbackData = IntPtr.Zero; // A pointer to a data buffer used to pass policy-specific data to a policy provider. This member can be NULL.
    internal IntPtr pSIPClientData = IntPtr.Zero; // A pointer to a data buffer used to pass subject interface package (SIP)-specific data to a SIP provider. This member can be NULL.

    [MarshalAs(UnmanagedType.U4)]
    internal WTD_UI dwUIChoice = WTD_UI.WTD_UI_NONE; // Specifies the kind of user interface (UI) to be used.

    [MarshalAs(UnmanagedType.U4)]
    internal WTD_REVOKE fdwRevocationChecks = WTD_REVOKE.WTD_REVOKE_WHOLECHAIN; // Certificate revocation check options. This member can be set to add revocation checking to that done by the selected policy provider.

    [MarshalAs(UnmanagedType.U4)]
    internal WTD_CHOICE dwUnionChoice; // Specifies the union member to be used and, thus, the type of object for which trust will be verified.

    internal IntPtr UnionData; // Union of pFile, pCatalog, pBlob, pSgnr, pCert

    [MarshalAs(UnmanagedType.U4)]
    internal WTD_STATEACTION dwStateAction = WTD_STATEACTION.WTD_STATEACTION_IGNORE; // Specifies the action to be taken.

    internal IntPtr hWVTStateData = IntPtr.Zero; // A handle to the state data. The contents of this member depends on the value of the dwStateAction member.

    internal IntPtr pwszURLReference = IntPtr.Zero; // Reserved for future use. Set to NULL.

    [MarshalAs(UnmanagedType.U4)]
    internal WTD dwProvFlags = WTD.WTD_CACHE_ONLY_URL_RETRIEVAL; // DWORD value that specifies trust provider settings.

    [MarshalAs(UnmanagedType.U4)]
    internal WTD_UICONTEXT dwUIContext = WTD_UICONTEXT.WTD_UICONTEXT_EXECUTE; // A DWORD value that specifies the user interface context for the WinVerifyTrust function. This causes the text in the Authenticode dialog box to match the action taken on the file.

    internal IntPtr pSignatureSettings = IntPtr.Zero; // Pointer to a WINTRUST_SIGNATURE_SETTINGS structure.

    public void Dispose()
    {
        if (UnionData != IntPtr.Zero)
            Marshal.FreeHGlobal(UnionData);
    }
}