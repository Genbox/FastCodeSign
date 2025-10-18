using System.Formats.Asn1;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Genbox.FastCodeSign.Internal.WinPe.Spc;

[StructLayout(LayoutKind.Auto)]
internal readonly record struct SpcSipInfo(int Version, Guid Identifier)
{
    private const AsnEncodingRules RuleSet = AsnEncodingRules.DER;
    internal static readonly Oid ObjectIdentifier = new Oid("1.3.6.1.4.1.311.2.1.30", "SPC_SIPINFO_OBJID");
    internal static readonly Guid SecurityProviderGuid = new Guid("603bcc1f-4b59-4e08-b724-d2c6297ef351"); // https://devblogs.microsoft.com/powershell/behind-powershell-installer-for-windows-xp-windows-server-2003/

    internal byte[] Encode()
    {
        AsnWriter writer = new AsnWriter(RuleSet);
        using (writer.PushSequence())
        {
            writer.WriteInteger(Version);
            writer.WriteOctetString(Identifier.ToByteArray());
            writer.WriteInteger(0);
            writer.WriteInteger(0);
            writer.WriteInteger(0);
            writer.WriteInteger(0);
            writer.WriteInteger(0);
        }

        return writer.Encode();
    }
}