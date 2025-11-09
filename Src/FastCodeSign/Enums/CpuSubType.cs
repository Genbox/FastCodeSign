namespace Genbox.FastCodeSign.Enums;

[Flags]
public enum CpuSubType : uint
{
    // See https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/mach/machine.h#L138
    Any = uint.MaxValue
}