namespace Genbox.FastCodeSign.Internal.MachObject.Headers.Enums;

// https://github.com/apple-oss-distributions/Security/blob/3dab46a11f45f2ffdbd70e2127cc5a8ce4a1f222/OSX/libsecurity_codesigning/lib/codedirectory.h#L222C24-L222C40
// https://github.com/apple-oss-distributions/xnu/blob/e3723e1f17661b24996789d8afc084c0c3303b26/osfmk/kern/cs_blobs.h#L103
internal enum Supports
{
    EarliestVersion = 0x20001,
    SupportsScatter = 0x20100,
    SupportsTeamId = 0x20200,
    SupportsCodeLimit64 = 0x20300,
    SupportsExecSegment = 0x20400
}