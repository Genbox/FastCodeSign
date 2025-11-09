namespace Genbox.FastCodeSign.Enums;

public enum ArmCpuSubType : uint
{
    // See https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/mach/machine.h#L365

    All = 0,
    V4T = 5,
    V6 = 6,
    V5TEJ = 7,
    XSCALE = 8,
    V7 = 9,
    V7F = 10,
    V7S = 11,
    V7K = 12,
    V8 = 13,
    V6M = 14,
    V7M = 15,
    V7EM = 16,
    V8M = 17
}