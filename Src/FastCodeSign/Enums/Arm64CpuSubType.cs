using System.Diagnostics.CodeAnalysis;

namespace Genbox.FastCodeSign.Enums;

[SuppressMessage("Design", "CA1008:Enums should have zero value", Justification = "Apple names the zero value CPU_SUBTYPE_ARM64_ALL.")]
[Flags]
public enum Arm64CpuSubType : uint
{
    // See https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/mach/machine.h#L386

    None = 0,
    All = None,
    V8 = 1,
    E = 2,
}