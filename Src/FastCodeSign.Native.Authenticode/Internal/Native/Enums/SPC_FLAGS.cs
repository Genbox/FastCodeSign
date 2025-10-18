namespace Genbox.FastCodeSign.Internal.Native.Enums;

//https://learn.microsoft.com/en-us/windows/win32/seccrypto/signersignex2
internal enum SPC_FLAGS : uint
{
    NONE = 0,
    SPC_EXC_PE_PAGE_HASHES_FLAG = 0x10,
    SPC_INC_PE_IMPORT_ADDR_TABLE_FLAG = 0x20,
    SPC_INC_PE_DEBUG_INFO_FLAG = 0x40,
    SPC_INC_PE_RESOURCES_FLAG = 0x80,
    SPC_INC_PE_PAGE_HASHES_FLAG = 0x100,
    SIG_APPEND = 0x1000
}