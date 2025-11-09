using Genbox.FastCodeSign.Enums;

namespace Genbox.FastCodeSign.Models;

public readonly record struct FatObject(CpuType CpuType, Enum CpuSubType, ulong Offset, ulong Size, uint Align)
{
    public ReadOnlySpan<byte> GetSpan(ReadOnlySpan<byte> span) => span.Slice((int)Offset, (int)Size);
}