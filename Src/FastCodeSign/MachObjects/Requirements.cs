using System.Security.Cryptography.X509Certificates;
using Genbox.FastCodeSign.Extensions;
using Genbox.FastCodeSign.Internal;
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

    internal string GetDesignatedRequirementText() => _values.TryGetValue(RequirementType.Designated, out Requirement? requirement)
        ? requirement.ToString()
        : throw new InvalidOperationException("The requirements do not contain a designated requirement.");

    internal static string GetDesignatedRequirementText(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length < 12 || (CsMagic)ReadUInt32BigEndian(buffer) != CsMagic.Requirements)
            throw new InvalidDataException("Invalid requirements blob.");

        int length = ReadInt32BigEndian(buffer[4..]);
        int count = ReadInt32BigEndian(buffer[8..]);
        if (length < 12 || length > buffer.Length || count < 0 || count > (length - 12) / 8)
            throw new InvalidDataException("Invalid requirements blob length.");

        for (int i = 0; i < count; i++)
        {
            int indexOffset = 12 + (i * 8);
            if ((RequirementType)ReadUInt32BigEndian(buffer[indexOffset..]) != RequirementType.Designated)
                continue;

            int requirementOffset = ReadInt32BigEndian(buffer[(indexOffset + 4)..]);
            if (requirementOffset < 12 + (count * 8) || requirementOffset > length - 12)
                throw new InvalidDataException("Invalid designated requirement offset.");

            ReadOnlySpan<byte> requirement = buffer.Slice(requirementOffset, length - requirementOffset);
            if ((CsMagic)ReadUInt32BigEndian(requirement) != CsMagic.Requirement)
                throw new InvalidDataException("Invalid designated requirement blob.");

            int requirementLength = ReadInt32BigEndian(requirement[4..]);
            if (requirementLength < 12 || requirementLength > requirement.Length || ReadUInt32BigEndian(requirement[8..]) != 1)
                throw new InvalidDataException("Invalid designated requirement length.");

            Expr expression = Expr.Decode(requirement.Slice(12, requirementLength - 12), out int bytesConsumed);
            if (bytesConsumed != requirementLength - 12)
                throw new InvalidDataException("The designated requirement contains trailing data.");

            return expression.ToString();
        }

        throw new InvalidDataException("The requirements do not contain a designated requirement.");
    }

    public static Requirements CreateEmpty() => new Requirements();

    public static Requirements CreateAppleDevDefault(string identifier, X509Certificate2 cert)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        string profile = cert.GetAppleCertificateProfile() ?? throw new ArgumentException("The certificate is not an Apple developer certificate.", nameof(cert));

        //designated => identifier "<ident>"
        //and anchor apple generic
        //and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */
        //and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */
        //and certificate leaf[subject.OU] = <teamid>

        Expr certificateProfile = Expr.CertGeneric(0, profile, MatchOperation.Exists);

        if (profile == OidConstants.ExtDeveloperIdApplication)
            certificateProfile = Expr.And(Expr.CertGeneric(1, "1.2.840.113635.100.6.2.6", MatchOperation.Exists), certificateProfile);

        // FCS-004: The designated requirement must name the leaf's actual Apple certificate profile, not always Developer ID Application.
        Expr expr = Expr.And(Expr.Ident(identifier), Expr.And(Expr.AppleGenericAnchor, Expr.And(certificateProfile, Expr.CertField(0, "subject.OU", MatchOperation.Equal, cert.GetTeamId()))));

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