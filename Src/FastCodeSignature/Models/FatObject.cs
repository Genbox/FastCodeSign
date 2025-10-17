namespace Genbox.FastCodeSignature.Models;

public readonly record struct FatObject(uint CpuType, uint CpuSubType, ulong Offset, ulong Size, uint Align);