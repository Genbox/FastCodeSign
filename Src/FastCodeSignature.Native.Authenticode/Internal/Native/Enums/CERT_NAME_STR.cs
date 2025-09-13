namespace Genbox.FastCodeSignature.Internal.Native.Enums;

//https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certnametostra
internal enum CERT_NAME_STR : uint
{
    CERT_SIMPLE_NAME_STR = 1,
    CERT_OID_NAME_STR = 2,
    CERT_X500_NAME_STR = 3
}