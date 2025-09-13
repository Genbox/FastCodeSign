using System.Formats.Asn1;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Genbox.FastCodeSignature.Internal.WinPe.Enums;

namespace Genbox.FastCodeSignature.Internal.WinPe.Spc;

/// <summary>
/// <![CDATA[
/// SpcPeImageData ::= SEQUENCE {
///     flags    SpcPeImageFlags DEFAULT { includeResources },
///     file     SpcLink
/// } --#public--
///
/// SpcPeImageFlags ::= BIT STRING {
///     includeResources            (0),
///     includeDebugInfo            (1),
///     includeImportAddressTable   (2)
/// }
/// ]]>
/// </summary>
/// <param name="Flags">This field specifies which portions of the Windows PE file are hashed. It is a 2-bit value that is set to one of the SpcPeImageData flags. Although flags is always present, it is ignored when calculating the file hash for both signing and verification purposes.</param>
/// <param name="File">This field is always set to an SPCLink structure, even though the ASN.1 definitions designate file as optional.</param>
[StructLayout(LayoutKind.Auto)]
internal readonly record struct SpcPeImageData(SpcPeImageFlags Flags, SpcLink File)
{
    private const AsnEncodingRules RuleSet = AsnEncodingRules.DER;
    internal static readonly Oid ObjectIdentifier = new Oid("1.3.6.1.4.1.311.2.1.15", "SPC_PE_IMAGE_DATAOBJ");

    internal byte[] Encode()
    {
        AsnWriter writer = new AsnWriter(RuleSet);

        using (writer.PushSequence())
        {
            writer.WriteBitString([(byte)Flags]);

            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                writer.WriteEncodedValue(File.Encode());
        }

        return writer.Encode();
    }
}