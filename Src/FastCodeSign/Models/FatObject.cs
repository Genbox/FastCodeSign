namespace Genbox.FastCodeSign.Models;

public readonly record struct FatObject(uint CpuType, uint CpuSubType, ulong Offset, ulong Size, uint Align);