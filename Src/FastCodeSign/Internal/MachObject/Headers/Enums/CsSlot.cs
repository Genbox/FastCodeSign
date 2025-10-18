namespace Genbox.FastCodeSign.Internal.MachObject.Headers.Enums;

// https://github.com/apple-oss-distributions/xnu/blob/e3723e1f17661b24996789d8afc084c0c3303b26/osfmk/kern/cs_blobs.h#L110
internal enum CsSlot : uint
{
    CodeDirectory = 0, // slot index for CodeDirectory
    Info = 1,
    Requirements = 2,
    ResourceDir = 3,
    Application = 4,
    Entitlements = 5,
    EntitlementsDer = 7,
    LaunchConstraintSelf = 8,
    LaunchConstraintParent = 9,
    LaunchConstraintResponsible = 10,
    LibraryConstraint = 11,
    AlternateCodeDirectories = 0x1000, // first alternate CodeDirectory, if any
    Signature = 0x10000, // CMS Signature
    Identification = 0x10001,
    Ticket = 0x10002
}