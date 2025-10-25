namespace Genbox.FastCodeSign.MachObject.Enums;

// https://github.com/apple-oss-distributions/Security/blob/3dab46a11f45f2ffdbd70e2127cc5a8ce4a1f222/OSX/libsecurity_codesigning/lib/requirement.h#L189
public enum MatchOperation
{
    Exists, // anything but explicit "false" - no value stored
    Equal, // equal (CFEqual)
    Contains, // partial match (substring)
    BeginsWith, // partial match (initial substring)
    EndsWith, // partial match (terminal substring)
    LessThan, // less than (string with numeric comparison)
    GreaterThan, // greater than (string with numeric comparison)
    LessEqual, // less or equal (string with numeric comparison)
    GreaterEqual, // greater or equal (string with numeric comparison)
    On, // on (timestamp comparison)
    Before, // before (timestamp comparison)
    After, // after (timestamp comparison)
    OnOrBefore, // on or before (timestamp comparison)
    OnOrAfter, // on or after (timestamp comparison)
    Absent, // not present (kCFNull)
}