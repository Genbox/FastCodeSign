using System.Formats.Asn1;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Genbox.FastCodeSignature.Internal.WinPe.Spc;

/// <summary>
/// SpcSpOpusInfo is identified by SPC_SP_OPUS_INFO_OBJID (1.3.6.1.4.1.311.2.1.12) and is defined as follows:
/// <![CDATA[
///        SpcSpOpusInfo ::= SEQUENCE {
///         programName             [0] EXPLICIT SpcString OPTIONAL,
///         moreInfo                [1] EXPLICIT SpcLink OPTIONAL,
///     } --#public--
/// ]]>
/// </summary>
/// <param name="ProgramName">If publisher chooses not to specify a description, the SpcString structure contains a zerolength program name.</param>
/// <param name="MoreInfo">This field is set to an SPCLink structure that contains a URL for a Web site with more information about the signer. The URL is an ASCII string.</param>
[StructLayout(LayoutKind.Auto)]
internal readonly record struct SpcSpOpusInfo(SpcString? ProgramName, SpcLink? MoreInfo)
{
    internal static readonly Oid ObjectIdentifier = new Oid("1.3.6.1.4.1.311.2.1.12", "SPC_SP_OPUS_INFO_OBJID");
    private const AsnEncodingRules RuleSet = AsnEncodingRules.DER;

    internal byte[] Encode()
    {
        AsnWriter writer = new AsnWriter(RuleSet);

        using (writer.PushSequence())
        {
            if (ProgramName != null)
            {
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                    writer.WriteEncodedValue(ProgramName.Value.Encode());
            }

            if (MoreInfo != null)
            {
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1, true)))
                    writer.WriteEncodedValue(MoreInfo.Value.Encode());
            }
        }

        return writer.Encode();
    }
}