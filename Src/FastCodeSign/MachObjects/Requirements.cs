using System.Security.Cryptography.X509Certificates;
using Genbox.FastCodeSign.Extensions;
using Genbox.FastCodeSign.Internal.MachObject;
using Genbox.FastCodeSign.Internal.MachObject.Headers.Enums;
using Genbox.FastCodeSign.MachObjects.Enums;

namespace Genbox.FastCodeSign.MachObjects;

public class Requirements
{
    private readonly Dictionary<RequirementType, Requirement> _values = new Dictionary<RequirementType, Requirement>();

    public void Add(RequirementType type, Expr expr)
    {
        if (!Enum.IsDefined(type))
            throw new ArgumentException("Invalid requirement type: " + type);

        ArgumentNullException.ThrowIfNull(expr);

        _values.Add(type, new Requirement(expr));
    }

    public void Remove(RequirementType type) => _values.Remove(type);

    private int Size => 12 + _values.Sum(x => x.Value.Size + 8); //Requirements header + blob index header + data size

    public void EncodeTo(Span<byte> buffer)
    {
        WriteUInt32BigEndian(buffer, (uint)CsMagic.Requirements);
        WriteInt32BigEndian(buffer[4..], Size);
        WriteInt32BigEndian(buffer[8..], _values.Count);

        int offset = 12 + (_values.Count * 8);

        int i = 0;
        foreach (KeyValuePair<RequirementType, Requirement> pair in _values)
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

    public override string ToString() => string.Join(", ", _values.Select(x => $"{x.Key.ToString().ToLowerInvariant()} => {x.Value}"));

    public static Requirements CreateEmpty() => new Requirements();

    public static Requirements CreateAppleDevDefault(string identifier, X509Certificate2 cert)
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

        Requirements req = new Requirements();
        req.Add(RequirementType.Designated, expr);
        return req;
    }

    public static Requirements CreateDefault(string identifier, X509Certificate2 cert)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        // identifier "<ident>"
        // and certificate leaf = H"<hash>"

        Expr expr = Expr.And(
            Expr.Ident(identifier),
            Expr.AnchorHash(0, Convert.FromHexString(cert.Thumbprint))
        );

        Requirements req = new Requirements();
        req.Add(RequirementType.Designated, expr);
        return req;
    }
}