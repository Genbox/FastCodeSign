namespace Genbox.FastCodeSign.Internal.Native.Enums;

//https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data
internal enum WTD_UI : uint
{
    /// <summary>Display all UI.</summary>
    WTD_UI_ALL = 1,

    /// <summary>Display no UI.</summary>
    WTD_UI_NONE = 2,

    /// <summary>Do not display any negative UI.</summary>
    WTD_UI_NOBAD = 3,

    /// <summary>Do not display any positive UI.</summary>
    WTD_UI_NOGOOD = 4
}