namespace Genbox.FastCodeSign.Internal;

internal static class OidConstants
{
    internal const string MD5 = "1.2.840.113549.2.5";
    internal const string SHA1 = "1.3.14.3.2.26";
    internal const string SHA256 = "2.16.840.1.101.3.4.2.1";
    internal const string SHA384 = "2.16.840.1.101.3.4.2.2";
    internal const string SHA512 = "2.16.840.1.101.3.4.2.3";

    internal const string OrganizationalUnit = "2.5.4.11";

    internal const string MsNestedSignature = "1.3.6.1.4.1.311.2.4.1"; // Ms-SpcNestedSignature
    internal const string MsCounterSign = "1.3.6.1.4.1.311.3.3.1"; // Timestamping signature (Ms-CounterSign)
    internal const string MsKeyPurpose = "1.3.6.1.4.1.311.2.1.21"; // SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID
    internal const string SigningTime = "1.2.840.113549.1.9.5"; // SigningTime attribute
    internal const string ApplePListAttrOid = "1.2.840.113635.100.9.1";
    internal const string AppleHashAttrOid = "1.2.840.113635.100.9.2";

    // Source: https://images.apple.com/certificateauthority/pdf/Apple_Developer_ID_CPS_v4.0.pdf
    // See section 4.11.2 Application Code Signing Certificates

    internal const string ExtAppleSigning = "1.2.840.113635.100.6.1.1";
    internal const string ExtIPhoneDeveloper = "1.2.840.113635.100.6.1.2";
    internal const string ExtIPhoneOsApplicationSigning = "1.2.840.113635.100.6.1.3";
    internal const string ExtAppleDeveloperCertificateSubmission = "1.2.840.113635.100.6.1.4";
    internal const string ExtSafariDeveloper = "1.2.840.113635.100.6.1.5";
    internal const string ExtIPhoneOsVpnSigning = "1.2.840.113635.100.6.1.6";
    internal const string ExtAppleMacAppSigningDevelopment = "1.2.840.113635.100.6.1.7";
    internal const string ExtAppleMacAppSigningSubmission = "1.2.840.113635.100.6.1.8";
    internal const string ExtAppleMacAppStoreCodeSigning = "1.2.840.113635.100.6.1.9";
    internal const string ExtAppleMacAppStoreInstallerSigning = "1.2.840.113635.100.6.1.10";
    internal const string ExtMacDeveloper = "1.2.840.113635.100.6.1.12";
    internal const string ExtDeveloperIdApplication = "1.2.840.113635.100.6.1.13";
    internal const string ExtDeveloperIdDate = "1.2.840.113635.100.6.1.33";
    internal const string ExtDeveloperIdInstaller = "1.2.840.113635.100.6.1.14";
    internal const string ExtApplePayPassbookSigning = "1.2.840.113635.100.6.1.16";
    internal const string ExtWebsitePushNotificationSigning = "1.2.840.113635.100.6.1.17";
    internal const string ExtDeveloperIdKernel = "1.2.840.113635.100.6.1.18";
    internal const string ExtTestFlight = "1.2.840.113635.100.6.1.25.1";
}