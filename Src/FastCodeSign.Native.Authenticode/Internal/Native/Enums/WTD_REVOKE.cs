namespace Genbox.FastCodeSign.Internal.Native.Enums;

//https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data
internal enum WTD_REVOKE : uint
{
    /// <summary>
    /// No additional revocation checking will be done when the WTD_REVOKE_NONE flag is used in conjunction with the HTTPSPROV_ACTION value set in the pgActionID parameter of the WinVerifyTrust function.
    /// To ensure the WinVerifyTrust function does not attempt any network retrieval when verifying code signatures, WTD_CACHE_ONLY_URL_RETRIEVAL must be set in the dwProvFlags parameter.
    /// </summary>
    WTD_REVOKE_NONE = 0,

    /// <summary>Revocation checking will be done on the whole chain.</summary>
    WTD_REVOKE_WHOLECHAIN = 1
}