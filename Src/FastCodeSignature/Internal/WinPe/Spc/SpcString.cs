using System.Formats.Asn1;

namespace Genbox.FastCodeSignature.Internal.WinPe.Spc;

/// <summary>
/// SpcString ::= CHOICE {
/// unicode     [0] IMPLICIT BMPSTRING,
/// ascii       [1] IMPLICIT IA5STRING
/// }
/// </summary>
/// <param name="Unicode"></param>
/// <param name="Ascii"></param>
internal readonly record struct SpcString(string? Unicode = null, string? Ascii = null)
{
    private const AsnEncodingRules RuleSet = AsnEncodingRules.DER;

    internal static SpcString Decode(ReadOnlySpan<byte> span)
    {
        string? unicode = null;
        string? ascii = null;

        Asn1Tag tag = AsnDecoder.ReadEncodedValue(span, RuleSet, out int _, out int _, out int _);
        if (tag.TagValue == 0)
            unicode = AsnDecoder.ReadCharacterString(span, RuleSet, UniversalTagNumber.BMPString, out int _, tag);
        else if (tag.TagValue == 1)
            ascii = AsnDecoder.ReadCharacterString(span, RuleSet, UniversalTagNumber.IA5String, out int _, tag);
        else
            throw new NotSupportedException($"Unsupported choice: {tag}");

        return new SpcString(unicode, ascii);
    }

    public byte[] Encode()
    {
        AsnWriter writer = new AsnWriter(RuleSet);

        if (Unicode != null)
            writer.WriteCharacterString(UniversalTagNumber.BMPString, Unicode, new Asn1Tag(TagClass.ContextSpecific, 0));
        else if (Ascii != null)
            writer.WriteCharacterString(UniversalTagNumber.IA5String, Ascii, new Asn1Tag(TagClass.ContextSpecific, 1));

        return writer.Encode();
    }
}