namespace Genbox.FastCodeSignature.Internal.MachObject.Headers.Enums;

// https://github.com/apple-oss-distributions/xnu/blob/e3723e1f17661b24996789d8afc084c0c3303b26/EXTERNAL_HEADERS/mach-o/loader.h#L264
[Flags]
public enum LoadCommandType : uint
{
    SEGMENT = 0x1, // segment of this file to be mapped
    SYMTAB = 0x2, // link-edit stab symbol table info
    SYMSEG = 0x3, // link-edit gdb symbol table info (obsolete)
    THREAD = 0x4, // thread
    UNIXTHREAD = 0x5, // unix thread (includes a stack)
    LOADFVMLIB = 0x6, // load a specified fixed VM shared library
    IDFVMLIB = 0x7, // fixed VM shared library identification
    IDENT = 0x8, // object identification info (obsolete)
    FVMFILE = 0x9, // fixed VM file inclusion (internal use)
    PREPAGE = 0xa, // prepage command (internal use)
    DYSYMTAB = 0xb, // dynamic link-edit symbol table info
    LOAD_DYLIB = 0xc, // load a dynamically linked shared library
    ID_DYLIB = 0xd, // dynamically linked shared lib ident
    LOAD_DYLINKER = 0xe, // load a dynamic linker
    ID_DYLINKER = 0xf, // dynamic linker identification
    PREBOUND_DYLIB = 0x10, // modules prebound for a dynamically
    ROUTINES = 0x11, // image routines
    SUB_FRAMEWORK = 0x12, // sub framework
    SUB_UMBRELLA = 0x13, // sub umbrella
    SUB_CLIENT = 0x14, // sub client
    SUB_LIBRARY = 0x15, // sub library
    TWOLEVEL_HINTS = 0x16, // two-level namespace lookup hints
    PREBIND_CKSUM = 0x17, // prebind checksum
    LOAD_WEAK_DYLIB = 0x18 | 0x80000000,
    SEGMENT_64 = 0x19, // 64-bit segment of this file to be mapped
    ROUTINES_64 = 0x1a, // 64-bit image routines
    UUID = 0x1b, // the uuid
    RPATH = 0x1c | 0x80000000, // runpath additions
    CODE_SIGNATURE = 0x1d, // local of code signature
    SEGMENT_SPLIT_INFO = 0x1e, // local of info to split segments
    REEXPORT_DYLIB = 0x1f | 0x80000000, // load and re-export dylib
    LAZY_LOAD_DYLIB = 0x20, // delay load of dylib until first use
    ENCRYPTION_INFO = 0x21, // encrypted segment information
    DYLD_INFO = 0x22, // compressed dyld information
    DYLD_INFO_ONLY = 0x22 | 0x80000000, // compressed dyld information only
    LOAD_UPWARD_DYLIB = 0x23 | 0x80000000, // load upward dylib
    VERSION_MIN_MACOSX = 0x24, // build for MacOSX min OS version
    VERSION_MIN_IPHONEOS = 0x25, // build for iPhoneOS min OS version
    FUNCTION_STARTS = 0x26, // compressed table of function start addresses
    DYLD_ENVIRONMENT = 0x27, // string for dyld to treat like environment variable
    MAIN = 0x28 | 0x80000000, // replacement for LC_UNIXTHREAD
    DATA_IN_CODE = 0x29, // table of non-instructions in __text
    SOURCE_VERSION = 0x2A, // source version used to build binary
    DYLIB_CODE_SIGN_DRS = 0x2B, // Code signing DRs copied from linked dylibs
    ENCRYPTION_INFO_64 = 0x2C, // 64-bit encrypted segment information
    LINKER_OPTION = 0x2D, // linker options in MH_OBJECT files
    LINKER_OPTIMIZATION_HINT = 0x2E, // optimization hints in MH_OBJECT files
    VERSION_MIN_TVOS = 0x2F, // build for AppleTV min OS version
    VERSION_MIN_WATCHOS = 0x30, // build for Watch min OS version
    NOTE = 0x31, // arbitrary data included within a Mach-O file
    BUILD_VERSION = 0x32, // build for platform min OS version
    DYLD_EXPORTS_TRIE = 0x33 | 0x80000000, // used with linkedit_data_command, payload is trie
    DYLD_CHAINED_FIXUPS = 0x34 | 0x80000000, // used with linkedit_data_command
    FILESET_ENTRY = 0x35 | 0x80000000 // used with fileset_entry_command
}