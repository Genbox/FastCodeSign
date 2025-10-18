namespace Genbox.FastCodeSign.Internal.MachObject.Headers.Enums;

// https://github.com/apple-oss-distributions/xnu/blob/e3723e1f17661b24996789d8afc084c0c3303b26/osfmk/kern/cs_blobs.h#L78
[Flags]
internal enum ExecSegFlags : ulong
{
    None = 0,
    MainBinary = 0x1, // executable segment denotes main binary
    AllowUnsigned = 0x10, // allow unsigned pages (for debugging)
    Debugger = 0x20, // main binary is debugger
    Jit = 0x40, // JIT enabled
    SkipLibraryValidation = 0x80, // OBSOLETE: skip library validation
    CanLoadCdHash = 0x100, // can bless cdhash for execution
    CanExecuteCdHash = 0x200 // can execute blessed cdhash
}