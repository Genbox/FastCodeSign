namespace Genbox.FastCodeSign.Enums;

public enum I386CpuSubType : uint
{
    // See https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/mach/machine.h#L259

    All = 3 + (0 << 4),
    I386 = 3 + (0 << 4),
    I486 = 4 + (0 << 4),
    I486SX = 4 + (8 << 4),
    I586 = 5 + (0 << 4),
    Pentium1 = 5 + (0 << 4),
    Pentium1Pro = 6 + (1 << 4),
    Pentium2M3 = 6 + (3 << 4),
    Pentium2M5 = 6 + (5 << 4),
    Celeron = 7 + (6 << 4),
    CeleronMobile = 7 + (7 << 4),
    Pentium3 = 8 + (0 << 4),
    Pentium3M = 8 + (1 << 4),
    Pentium3Xeon = 8 + (2 << 4),
    PentiumM = 9 + (0 << 4),
    Pentium4 = 10 + (0 << 4),
    Pentium4M = 10 + (1 << 4),
    Itanium = 11 + (0 << 4),
    Itanium2 = 11 + (1 << 4),
    Xeon = 12 + (0 << 4),
    XeonMP = 12 + (1 << 4),
}