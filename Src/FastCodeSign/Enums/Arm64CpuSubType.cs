namespace Genbox.FastCodeSign.Enums;

[Flags]
public enum Arm64CpuSubType : uint
{
    // See https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/mach/machine.h#L386

    All = 0,
    V8 = 1,
    E = 2,
}