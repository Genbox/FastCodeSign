namespace Genbox.FastCodeSignature.Internal.Native.Enums;

//https://learn.microsoft.com/en-us/windows/win32/seccrypto/signersignex3
[Flags]
internal enum SPCEx3 : uint
{
    NONE = 0,
    SPC_EXC_PE_PAGE_HASHES_FLAG = 16,
    SPC_INC_PE_IMPORT_ADDR_TABLE_FLAG = 32,
    SPC_INC_PE_DEBUG_INFO_FLAG = 64,
    SPC_INC_PE_RESOURCES_FLAG = 128,
    SPC_INC_PE_PAGE_HASHES_FLAG = 256,
    SIGN_CALLBACK_UNDOCUMENTED = 1024,
    SPC_DIGEST_SIGN_FLAG = 2048,
    SIG_APPEND = 4096,
    SPC_DIGEST_SIGN_EX_FLAG = 16384
}