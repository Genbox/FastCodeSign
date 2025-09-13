using System.Security.Cryptography.X509Certificates;
using Genbox.FastCodeSignature.Internal.MachObject.Headers.Enums;
using Genbox.FastCodeSignature.Internal.MachObject.Requirements.Enums;

namespace Genbox.FastCodeSignature.Internal.MachObject.Requirements;

public class RequirementSet : Dictionary<RequirementType, Requirement>
{
    public override string ToString() => string.Join(", ", this.Select(x => $"{x.Key}: {x.Value}"));

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

    public static RequirementSet CreateAppleDevDefault(string identifier, X509Certificate2 cert)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        Expression expression = Expression.And(
            Expression.Ident(identifier),
            Expression.And(
                Expression.AppleGenericAnchor,
                Expression.And(
                    Expression.CertField(0, "subject.CN", MatchOperation.Equal, cert.SubjectName.Name),
                    Expression.CertGeneric(1, "1.2.840.113635.100.6.2.1", MatchOperation.Exists)
                )
            )
        );

        return new RequirementSet { { RequirementType.Designated, new Requirement(expression) } };
    }

    public static RequirementSet CreateDefault(string identifier, X509Certificate2 cert)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        // identifier "Default_unsigned" and certificate leaf = H"ee6fc96aaf31858586f0f6e0b70c2e11f2f232ad"

        Expression expression = Expression.And(
            Expression.Ident(identifier),
            Expression.AnchorHash(0, Convert.FromHexString(cert.Thumbprint))
        );

        return new RequirementSet { { RequirementType.Designated, new Requirement(expression) } };
    }
}