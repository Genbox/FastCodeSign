namespace Genbox.FastCodeSignature.Internal.MachObject.Headers.Enums;

// https://github.com/apple-oss-distributions/xnu/blob/e3723e1f17661b24996789d8afc084c0c3303b26/osfmk/kern/cs_blobs.h#L36C1-L58C108
[Flags]
internal enum CdFlags : uint
{
    None = 0,
    Valid = 0x00000001, // dynamically valid
    Adhoc = 0x00000002, // ad hoc signed
    GetTaskAllow = 0x00000004, // has get-task-allow entitlement
    Installer = 0x00000008, // has installer entitlement
    ForcedLibraryValidation = 0x00000010, // Library Validation required by Hardened System Policy
    InvalidAllowed = 0x00000020, // (macOS Only) Page invalidation allowed by task port policy
    Hard = 0x00000100, // don't load invalid pages
    Kill = 0x00000200, // kill process if it becomes invalid
    CheckExpiration = 0x00000400, // force expiration checking
    Restrict = 0x00000800, // tell dyld to treat restricted
    Enforcement = 0x00001000, // require enforcement
    RequireLibraryValidation = 0x00002000, // require library validation
    EntitlementsValidated = 0x00004000, // code signature permits restricted entitlements
    NvramUnrestricted = 0x00008000, // has com.apple.rootless.restricted-nvram-variables.heritable entitlement
    Runtime = 0x00010000, // Apply hardened runtime policies
    LinkerSigned = 0x00020000 // Automatically signed by the linker
}