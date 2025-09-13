namespace Genbox.FastCodeSignature.Internal.MachObject.Requirements.Enums;

// https://github.com/apple-oss-distributions/Security/blob/3dab46a11f45f2ffdbd70e2127cc5a8ce4a1f222/OSX/libsecurity_codesigning/lib/CSCommon.h#L361
public enum RequirementType : uint
{
    Host = 1, // what hosts may run us
    Guest = 2, // what guests we may run
    Designated = 3, // designated requirement
    Library = 4, // what libraries we may link against
    Plugin = 5, // what plug-ins we may load
    Invalid // invalid type of Requirement (must be last)
}