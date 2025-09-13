namespace Genbox.FastCodeSignature.Internal.Native.Enums;

//https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data
internal enum WTD_CHOICE : uint
{
    WTD_CHOICE_FILE = 1,
    WTD_CHOICE_CATALOG = 2,
    WTD_CHOICE_BLOB = 3,
    WTD_CHOICE_SIGNER = 4,
    WTD_CHOICE_CERT = 5
}