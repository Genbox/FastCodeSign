namespace Genbox.FastCodeSignature;

public readonly record struct FatObject(uint CpuType, uint CpuSubType, ulong Offset, ulong Size, uint Align);