using Genbox.FastCodeSign.Enums;

namespace Genbox.FastCodeSign.Models;

public readonly record struct MachObject(CpuType CpuType, Enum CpuSubType, ulong Offset, ulong Size, uint Align)
{
    public Span<byte> GetSpan(Span<byte> span) => span.Slice((int)Offset, (int)Size);
}