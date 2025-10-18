namespace Genbox.FastCodeSign.Internal.Native.Enums;

//https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-crypt_provider_cert
[Flags]
internal enum CERT_CONFIDENCE : uint
{
    CERT_CONFIDENCE_SIG = 0x10000000,
    CERT_CONFIDENCE_TIME = 0x01000000,
    CERT_CONFIDENCE_TIMENEST = 0x00100000,
    CERT_CONFIDENCE_AUTHIDEXT = 0x00010000,
    CERT_CONFIDENCE_HYGIENE = 0x00001000,
    CERT_CONFIDENCE_HIGHEST = 0x11111000
}