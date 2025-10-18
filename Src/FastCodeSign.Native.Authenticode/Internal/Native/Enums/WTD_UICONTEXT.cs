namespace Genbox.FastCodeSign.Internal.Native.Enums;

//https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data
internal enum WTD_UICONTEXT : uint
{
    /// <summary>
    /// Use when calling WinVerifyTrust for a file that is to be run. This is the default value.
    /// </summary>
    WTD_UICONTEXT_EXECUTE = 0,

    /// <summary>
    /// Use when calling WinVerifyTrust for a file that is to be installed.
    /// </summary>
    WTD_UICONTEXT_INSTALL = 1
}