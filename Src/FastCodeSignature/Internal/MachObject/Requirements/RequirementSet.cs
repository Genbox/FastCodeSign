using System.Security.Cryptography.X509Certificates;
using Genbox.FastCodeSignature.Extensions;
using Genbox.FastCodeSignature.Internal.MachObject.Headers.Enums;
using Genbox.FastCodeSignature.Internal.MachObject.Requirements.Enums;

namespace Genbox.FastCodeSignature.Internal.MachObject.Requirements;

public class RequirementSet : Dictionary<RequirementType, Requirement>
{
    private RequirementSet() {}

    public int Size => 12 + this.Sum(x => x.Value.Size + 8); //Requirements header + blob index header + data size

    public void EncodeTo(Span<byte> buffer)
    {
        WriteUInt32BigEndian(buffer, (uint)CsMagic.Requirements);
        WriteInt32BigEndian(buffer[4..], Size);
        WriteInt32BigEndian(buffer[8..], Count);

        int offset = 12 + (Count * 8);

        int i = 0;
        foreach (KeyValuePair<RequirementType, Requirement> pair in this)
        {
            WriteUInt32BigEndian(buffer.Slice(12 + (i * 8), 4), (uint)pair.Key);
            WriteInt32BigEndian(buffer.Slice(12 + (i * 8) + 4, 4), offset);

            pair.Value.EncodeTo(buffer[offset..]);
            offset += pair.Value.Size;
            i++;
        }
    }

    public byte[] ToArray()
    {
        byte[] buffer = new byte[Size];
        EncodeTo(buffer);
        return buffer;
    }

    public override string ToString() => string.Join(", ", this.Select(x => $"{x.Key.ToString().ToLowerInvariant()} => {x.Value}"));

    public static RequirementSet CreateEmpty() => new RequirementSet();

    public static RequirementSet CreateAppleDevDefault(string identifier, X509Certificate2 cert)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        //designated => identifier "<ident>"
        //and anchor apple generic
        //and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */
        //and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */
        //and certificate leaf[subject.OU] = <teamid>

        Expr expr = Expr.And(
            Expr.Ident(identifier),
            Expr.And(
                Expr.AppleGenericAnchor,
                Expr.And(
                    Expr.CertGeneric(1, "1.2.840.113635.100.6.2.6", MatchOperation.Exists),
                    Expr.And(
                        Expr.CertGeneric(0, "1.2.840.113635.100.6.1.13", MatchOperation.Exists),
                        Expr.CertField(0, "subject.OU", MatchOperation.Equal, cert.GetTeamId())
                    )
                )
            )
        );

        return new RequirementSet { { RequirementType.Designated, new Requirement(expr) } };
    }

    public static RequirementSet CreateDefault(string identifier, X509Certificate2 cert)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        // identifier "<ident>"
        // and certificate leaf = H"<hash>"

        Expr expression = Expr.And(
            Expr.Ident(identifier),
            Expr.AnchorHash(0, Convert.FromHexString(cert.Thumbprint))
        );

        return new RequirementSet { { RequirementType.Designated, new Requirement(expression) } };
    }
}