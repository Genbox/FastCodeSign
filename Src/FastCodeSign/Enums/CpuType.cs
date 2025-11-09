namespace Genbox.FastCodeSign.Enums;

public enum CpuType : uint
{
    // See https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/mach/machine.h#L138

    VAX = 1,
    MC680x0 = 6,
    X86 = 7,
    // I386  = X86,
    X86_64 = X86 | ABI64,

    MC98000 = 10,
    HPPA = 11,
    ARM = 12,
    ARM64 = ARM | ABI64,
    ARM64_32 = ARM | ABI64_32,
    MC88000 = 13,
    SPARC = 14,
    I860 = 15,

    PowerPC = 18,
    PowerPC64 = PowerPC | ABI64,

    ABI64 = 0x1000000,
    ABI64_32 = 0x2000000,
}