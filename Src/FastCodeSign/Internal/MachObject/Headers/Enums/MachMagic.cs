namespace Genbox.FastCodeSign.Internal.MachObject.Headers.Enums;

internal enum MachMagic : uint
{
    //https://github.com/apple-oss-distributions/cctools/blob/483f452caad0ebe3fbe198d3f8c2b1bea848df6c/include/mach-o/loader.h#L73
    MachMagicBE = 0xfeed_face,
    MachMagicLE = 0xcefa_edfe,

    //https://github.com/apple-oss-distributions/cctools/blob/483f452caad0ebe3fbe198d3f8c2b1bea848df6c/include/mach-o/loader.h#L92
    MachMagic64BE = 0xfeed_facf,
    MachMagic64LE = 0xcffa_edfe,

    //https://github.com/apple-oss-distributions/cctools/blob/483f452caad0ebe3fbe198d3f8c2b1bea848df6c/include/mach-o/fat.h#L54
    FatMagicBE = 0xcafe_babe,
    FatMagicLE = 0xbeba_feca,

    //https://github.com/apple-oss-distributions/cctools/blob/483f452caad0ebe3fbe198d3f8c2b1bea848df6c/include/mach-o/fat.h#L77
    FatMagic64BE = 0xcafe_babf,
    FatMagic64LE = 0xbfba_feca
}