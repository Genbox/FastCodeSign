using System.Diagnostics.CodeAnalysis;
using Genbox.FastCodeSign.Enums;

namespace Genbox.FastCodeSign.Models;

[SuppressMessage("Naming", "CA1724:Type names should not match namespaces", Justification = "MachObject is the domain model for a Mach-O slice.")]
public readonly record struct MachObject(CpuType CpuType, Enum CpuSubType, ulong Offset, ulong Size, uint Align)
{
    public Span<byte> GetSpan(Span<byte> span) => span.Slice((int)Offset, (int)Size);
    public ReadOnlySpan<byte> GetSpan(ReadOnlySpan<byte> span) => span.Slice((int)Offset, (int)Size);
}