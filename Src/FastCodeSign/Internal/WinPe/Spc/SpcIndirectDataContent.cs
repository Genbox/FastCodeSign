using System.Formats.Asn1;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Genbox.FastCodeSign.Internal.Helpers;

namespace Genbox.FastCodeSign.Internal.WinPe.Spc;

/// <summary>
/// The root structure inside ContentInfo is SpcIndirectDataContent.
/// <![CDATA[
/// SpcIndirectDataContent ::= SEQUENCE {
///     data SpcAttributeTypeAndOptionalValue,
///     messageDigest DigestInfo
/// } --#public—
/// 
/// SpcAttributeTypeAndOptionalValue ::= SEQUENCE {
///     type ObjectID,
///     value [0] EXPLICIT ANY OPTIONAL
/// }
/// 
/// DigestInfo ::= SEQUENCE {
///     digestAlgorithm AlgorithmIdentifier,
///     digest OCTETSTRING
/// }
/// 
/// AlgorithmIdentifier ::= SEQUENCE {
///     algorithm ObjectID,
///     parameters [0] EXPLICIT ANY OPTIONAL
/// }
/// ]]>
/// </summary>
/// <param name="Data">This field is set to an SpcAttributeTypeAndOptionalValue structure.</param>
/// <param name="DigestAlgorithm">This field specifies the digest algorithm that is used to hash the file. The value must match the digestAlgorithm value specified in SignerInfo and the parent PKCS #7 digestAlgorithms fields.</param>
/// <param name="Digest">This field is set to the message digest value of the file.</param>
/// <param name="DataType">This field is set to an SpcAttributeTypeAndOptionalValue structure.</param>
[StructLayout(LayoutKind.Auto)]
internal readonly record struct SpcIndirectDataContent(byte[]? Data, Oid DataType, Oid DigestAlgorithm, byte[] Digest, byte[]? DigestParameters)
{
    private const AsnEncodingRules RuleSet = AsnEncodingRules.DER;
    internal static readonly Oid ObjectIdentifier = new Oid("1.3.6.1.4.1.311.2.1.4", "SPC_INDIRECT_DATA_OBJID");

    internal static SpcIndirectDataContent Decode(ReadOnlySpan<byte> span)
    {
        AsnDecoder.ReadSequence(span, RuleSet, out int offset, out int length, out int consumed);
        span = span.Slice(offset, length);

        AsnDecoder.ReadSequence(span, RuleSet, out offset, out length, out consumed);
        ReadOnlySpan<byte> dataSequence = span.Slice(offset, length);
        span = span[consumed..];

        Oid dataType = new Oid(AsnDecoder.ReadObjectIdentifier(dataSequence, RuleSet, out consumed));
        dataSequence = dataSequence[consumed..];

        byte[]? data = Asn1Helper.GetNullableBytes(dataSequence);

        AsnDecoder.ReadSequence(span, RuleSet, out offset, out length, out consumed);
        ReadOnlySpan<byte> digestSequence = span.Slice(offset, length);

        AsnDecoder.ReadSequence(digestSequence, RuleSet, out offset, out length, out consumed);
        ReadOnlySpan<byte> algorithmSequence = digestSequence.Slice(offset, length);
        digestSequence = digestSequence[consumed..];

        Oid digestAlgorithm = new Oid(AsnDecoder.ReadObjectIdentifier(algorithmSequence, RuleSet, out consumed));
        algorithmSequence = algorithmSequence[consumed..];

        byte[]? digestParameters = Asn1Helper.GetNullableBytes(algorithmSequence);
        byte[] digest = AsnDecoder.ReadOctetString(digestSequence, RuleSet, out consumed);

        return new SpcIndirectDataContent(data, dataType, digestAlgorithm, digest, digestParameters);
    }

    public byte[] Encode()
    {
        AsnWriter writer = new AsnWriter(RuleSet);
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(DataType.Value!);
                if (Data == null)
                    writer.WriteNull();
                else
                    writer.WriteEncodedValue(Data);
            }

            using (writer.PushSequence())
            {
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(DigestAlgorithm.Value!);

                    if (DigestParameters == null)
                        writer.WriteNull();
                    else
                        writer.WriteEncodedValue(DigestParameters);
                }

                writer.WriteOctetString(Digest);
            }
        }

        return writer.Encode();
    }
}