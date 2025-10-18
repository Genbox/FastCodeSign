using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace Genbox.FastCodeSign.Native.Authenticode;

public static class CryptUiSigner
{
    private const uint CRYPTUI_WIZ_NO_UI = 0x0001;
    private const uint CRYPTUI_WIZ_DIGITAL_SIGN_SUBJECT_FILE = 0x01; // dwSubjectChoice
    private const uint CRYPTUI_WIZ_DIGITAL_SIGN_CERT = 0x01; // dwSigningCertChoice

    public static void SignFile(string pathToFile, X509Certificate2 cert)
    {
        var info = new CRYPTUI_WIZ_DIGITAL_SIGN_INFO
        {
            dwSize = (uint)Marshal.SizeOf<CRYPTUI_WIZ_DIGITAL_SIGN_INFO>(),
            dwSubjectChoice = CRYPTUI_WIZ_DIGITAL_SIGN_SUBJECT_FILE,
            pwszFileName = pathToFile,
            dwSigningCertChoice = CRYPTUI_WIZ_DIGITAL_SIGN_CERT,
            pSigningCertContext = cert.Handle, // PCCERT_CONTEXT
            pwszTimestampURL = null, // no timestamp (minimal)
            dwAdditionalCertChoice = 0,
            pSignExtInfo = IntPtr.Zero
        };

        // Call the wizard in NO-UI mode
        if (!CryptUIWizDigitalSign(CRYPTUI_WIZ_NO_UI, IntPtr.Zero, null, ref info, out var pSignCtx))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        // Always free the context
        if (pSignCtx != IntPtr.Zero)
            CryptUIWizFreeDigitalSignContext(pSignCtx);
    }

    [DllImport("Cryptui.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CryptUIWizDigitalSign(
        uint dwFlags,
        IntPtr hwndParent,
        string? pwszWizardTitle,
        ref CRYPTUI_WIZ_DIGITAL_SIGN_INFO pDigitalSignInfo,
        out IntPtr ppSignContext);

    [DllImport("Cryptui.dll", SetLastError = true)]
    private static extern void CryptUIWizFreeDigitalSignContext(IntPtr pSignContext);

    // Minimal struct layout (file subject + cert context choice)
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CRYPTUI_WIZ_DIGITAL_SIGN_INFO
    {
        public uint dwSize;
        public uint dwSubjectChoice; // 1 = file
        [MarshalAs(UnmanagedType.LPWStr)]public string? pwszFileName;

        public uint dwSigningCertChoice; // 1 = cert context
        public IntPtr pSigningCertContext; // PCCERT_CONTEXT when dwSigningCertChoice==1

        [MarshalAs(UnmanagedType.LPWStr)]public string? pwszTimestampURL; // null for minimal
        public uint dwAdditionalCertChoice; // 0 for minimal
        public IntPtr pSignExtInfo; // optional extended info (null here)
    }
}