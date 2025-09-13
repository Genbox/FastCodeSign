using System.Formats.Asn1;
using System.Runtime.InteropServices;

namespace Genbox.FastCodeSignature.Internal.WinPe.Spc;

/// <summary>
/// <![CDATA[
///  SpcSerializedObject ::= SEQUENCE {
///      classId             SpcUuid,
///      serializedData      OCTETSTRING
///  }
///  SpcUuid ::= OCTETSTRING
/// ]]>
/// </summary>
/// <param name="ClassId">The SpcUuid field is set to the following 10-byte octet string (a globally unique identifier—GUID) if SpcSerializedObject is present:</param>
/// <param name="SerializedData">The serializedData field contains a binary structure. When present in an Authenticode signature generated in Windows Vista, serializedData contains a binary structure that contains page hashes.</param>
[StructLayout(LayoutKind.Auto)]
internal readonly record struct SpcSerializedObject(Guid ClassId, byte[] SerializedData)
{
    private const AsnEncodingRules RuleSet = AsnEncodingRules.DER;

    internal static SpcSerializedObject Decode(ReadOnlySpan<byte> span, Asn1Tag? expectedTag = null)
    {
        AsnDecoder.ReadSequence(span, RuleSet, out int offset, out int length, out int consumed, expectedTag);
        span = span.Slice(offset, length);

        byte[] classId = AsnDecoder.ReadOctetString(span, RuleSet, out consumed);
        span = span[consumed..];

        byte[] rawData = AsnDecoder.ReadOctetString(span, RuleSet, out consumed);

        return new SpcSerializedObject(new Guid(classId), rawData);
    }

    public byte[] Encode(Asn1Tag? tag = null)
    {
        AsnWriter writer = new AsnWriter(RuleSet);

        using (writer.PushSequence(tag))
        {
            writer.WriteOctetString(ClassId.ToByteArray());
            writer.WriteOctetString(SerializedData);
        }

        return writer.Encode();
    }
}