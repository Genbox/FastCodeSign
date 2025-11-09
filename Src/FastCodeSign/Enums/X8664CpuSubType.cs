namespace Genbox.FastCodeSign.Enums;

public enum X8664CpuSubType : uint
{
    All = 3,
    All_64 = 3 | Lib64,
    Haswell = 8,
    Haswell_64 = 8 | Lib64,

    Lib64 = 0x80000000
}