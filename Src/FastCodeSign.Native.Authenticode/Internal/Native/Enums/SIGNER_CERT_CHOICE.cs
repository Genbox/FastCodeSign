namespace Genbox.FastCodeSign.Internal.Native.Enums;

//https://learn.microsoft.com/en-us/windows/win32/seccrypto/signer-cert
internal enum SIGNER_CERT_CHOICE : uint
{
    SIGNER_CERT_SPC_FILE = 1,
    SIGNER_CERT_STORE = 2,
    SIGNER_CERT_SPC_CHAIN = 3
}