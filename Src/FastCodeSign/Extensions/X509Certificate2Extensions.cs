using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using static Genbox.FastCodeSign.Internal.OidConstants;

namespace Genbox.FastCodeSign.Extensions;

public static class X509Certificate2Extensions
{
    private static readonly string[] Oids =
    [
        ExtDeveloperIdApplication,
        ExtDeveloperIdKernel,
        ExtAppleMacAppSigningDevelopment,
        ExtAppleMacAppSigningSubmission,
        ExtAppleMacAppStoreCodeSigning,
        ExtAppleMacAppStoreInstallerSigning,
        ExtDeveloperIdInstaller,
        ExtIPhoneDeveloper,
        ExtIPhoneOsApplicationSigning,
        ExtAppleDeveloperCertificateSubmission,
        ExtSafariDeveloper,
        ExtIPhoneOsVpnSigning,
        ExtMacDeveloper,
        ExtApplePayPassbookSigning,
        ExtWebsitePushNotificationSigning,
        ExtTestFlight,
        ExtAppleSigning
    ];

    public static string? GetTeamId(this X509Certificate2 certificate)
    {
        AsnReader rdr = new AsnReader(certificate.SubjectName.RawData, AsnEncodingRules.DER);
        AsnReader rdrSeq = rdr.ReadSequence();

        while (rdrSeq.HasData)
        {
            AsnReader rdrInner = rdrSeq.ReadSetOf(skipSortOrderValidation: true);

            while (rdrInner.HasData)
            {
                AsnReader rdrSeq2 = rdrInner.ReadSequence();
                string oid = rdrSeq2.ReadObjectIdentifier();

                if (oid == OrganizationalUnit)
                    return ReadAnyAsnString(rdrSeq2);
            }
        }

        return null;
    }

    public static bool IsAppleDeveloperCertificate(this X509Certificate2 certificate)
        => certificate.GetAppleCertificateProfile() != null;

    internal static string? GetAppleCertificateProfile(this X509Certificate2 certificate)
    {
        foreach (string profile in Oids)
        {
            foreach (X509Extension extension in certificate.Extensions)
            {
                if (string.Equals(extension.Oid?.Value, profile, StringComparison.Ordinal))
                    return profile;
            }
        }

        return null;
    }

    private static string ReadAnyAsnString(AsnReader reader)
    {
        Asn1Tag tag = reader.PeekTag();

        if (tag.TagClass != TagClass.Universal)
            throw new InvalidOperationException("Invalid DER encoding");

        return (UniversalTagNumber)tag.TagValue switch
        {
            UniversalTagNumber.BMPString
                or UniversalTagNumber.IA5String
                or UniversalTagNumber.NumericString
                or UniversalTagNumber.PrintableString
                or UniversalTagNumber.UTF8String
                or UniversalTagNumber.T61String => reader.ReadCharacterString((UniversalTagNumber)tag.TagValue).TrimEnd('\0'),
            _ => throw new InvalidOperationException("Invalid DER encoding")
        };
    }
}