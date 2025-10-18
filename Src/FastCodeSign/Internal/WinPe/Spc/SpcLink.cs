using System.Formats.Asn1;
using System.Runtime.InteropServices;

namespace Genbox.FastCodeSign.Internal.WinPe.Spc;

/// <summary>
/// SPCLink originally contained information that describes the software publisher
/// <![CDATA[
/// SpcLink ::= CHOICE {
///     url                     [0] IMPLICIT IA5STRING,
///     moniker                 [1] IMPLICIT SpcSerializedObject,
///     file                    [2] EXPLICIT SpcString
/// } --#public--
/// ]]>
/// </summary>
/// <param name="Url">This choice is not supported, but it does not affect signature verification if present</param>
/// <param name="Moniker">This choice is set to an SpcSerializedObject structure</param>
/// <param name="File">This is the default choice. It is set to an SpcString structure, which contains a Unicode string set to &lt;&lt;&lt;Obsolete&gt;&gt;&gt;</param>
[StructLayout(LayoutKind.Auto)]
internal readonly record struct SpcLink(string? Url = null, SpcSerializedObject? Moniker = null, SpcString? File = null)
{
    private const AsnEncodingRules RuleSet = AsnEncodingRules.DER;

    internal static SpcLink Decode(ReadOnlySpan<byte> span)
    {
        Asn1Tag tag = AsnDecoder.ReadEncodedValue(span, RuleSet, out int offset, out int length, out int _);

        string? url = null;
        SpcSerializedObject? moniker = null;
        SpcString? file = null;

        if (tag.TagValue == 0)
            url = AsnDecoder.ReadCharacterString(span, RuleSet, UniversalTagNumber.IA5String, out int _, tag);
        else if (tag.TagValue == 1)
            moniker = SpcSerializedObject.Decode(span.Slice(offset, length), tag);
        else if (tag.TagValue == 2)
            file = SpcString.Decode(span.Slice(offset, length));

        return new SpcLink(url, moniker, file);
    }

    internal byte[] Encode()
    {
        AsnWriter writer = new AsnWriter(RuleSet);

        if (Url != null)
            writer.WriteCharacterString(UniversalTagNumber.IA5String, Url, new Asn1Tag(TagClass.ContextSpecific, 0));
        else if (Moniker != null)
            writer.WriteEncodedValue(Moniker.Value.Encode(new Asn1Tag(TagClass.ContextSpecific, 1, true)));
        else if (File != null)
        {
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2, true)))
                writer.WriteEncodedValue(File.Value.Encode());
        }

        return writer.Encode();
    }
}