namespace Genbox.FastCodeSign.Internal.Native.Enums;

//https://learn.microsoft.com/en-us/windows/win32/seccrypto/signertimestampex3
internal enum SIGNER_TIMESTAMP : uint
{
    None = 0,
    SIGNER_TIMESTAMP_AUTHENTICODE = 1,
    SIGNER_TIMESTAMP_RFC3161 = 2,
}