namespace Genbox.FastCodeSignature.Internal.Native.Enums;

//https://learn.microsoft.com/en-us/windows/win32/seccrypto/signer-signature-info
internal enum SIGNER : uint
{
    SIGNER_AUTHCODE_ATTR = 1,
    SIGNER_NO_ATTR = 0
}