using System.Formats.Asn1;
using System.Security.Cryptography;

namespace Genbox.FastCodeSign.Internal.WinPe.Spc;

internal sealed record SpcStatementType(Oid[] Oids)
{
    private const AsnEncodingRules RuleSet = AsnEncodingRules.DER;
    public static readonly Oid ObjectIdentifier = new Oid("1.3.6.1.4.1.311.2.1.11", "SPC_STATEMENT_TYPE_OBJID");

    public byte[] Encode()
    {
        AsnWriter writer = new AsnWriter(RuleSet);
        using (writer.PushSequence())
        {
            foreach (Oid oid in Oids)
                writer.WriteObjectIdentifier(oid.Value!);
        }

        return writer.Encode();
    }
}