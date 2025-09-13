using Genbox.FastCodeSignature.Internal.MachObject.Headers.Enums;

namespace Genbox.FastCodeSignature.Internal.MachObject.Requirements;

public class Requirement(Expression expression)
{
    public int Size => 12 + expression.Size;

    public void EncodeTo(Span<byte> buffer)
    {
        WriteUInt32BigEndian(buffer, (uint)CsMagic.Requirement);
        WriteInt32BigEndian(buffer[4..], Size);
        WriteUInt32BigEndian(buffer[8..], 1u); // Expression
        expression.Write(buffer[12..]);
    }

    public override string ToString() => expression.ToString();
}