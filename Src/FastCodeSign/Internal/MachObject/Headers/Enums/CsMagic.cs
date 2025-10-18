namespace Genbox.FastCodeSign.Internal.MachObject.Headers.Enums;

// https://github.com/apple-oss-distributions/xnu/blob/e3723e1f17661b24996789d8afc084c0c3303b26/osfmk/kern/cs_blobs.h#L92
internal enum CsMagic : uint
{
    Requirement = 0xfade_0c00, // Single Requirement blob
    Requirements = 0xfade_0c01, // Requirements vector (internal requirements)
    CodeDirectory = 0xfade_0c02, // CodeDirectory blob
    EmbeddedSignature = 0xfade_0cc0, // Embedded form of signature data
    Entitlements = 0xfade_7171, // Embedded entitlements
    EntitlementsDer = 0xfade_7172, // Embedded DER encoded entitlements
    DetachedSignature = 0xfade_0cc1, // Multi-arch collection of embedded signatures
    BlobWrapper = 0xfade_0b01, // CMS Signature, among other things
    EmbeddedLaunchConstraint = 0xfade_8181 // Light-weight code requirement
}