using Genbox.FastCodeSign.Internal.MachObject.Headers.Enums;
using Genbox.FastCodeSign.MachObjects;

namespace Genbox.FastCodeSign.Internal.MachObject;

internal class Requirement(Expr expression)
{
    internal int Size => 12 + expression.Size;

    internal void EncodeTo(Span<byte> buffer)
    {
        WriteUInt32BigEndian(buffer, (uint)CsMagic.Requirement);
        WriteInt32BigEndian(buffer[4..], Size);
        WriteUInt32BigEndian(buffer[8..], 1u); // Expression
        expression.Write(buffer[12..]);
    }

    public override string ToString() => expression.ToString();
}