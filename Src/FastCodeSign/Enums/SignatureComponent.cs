namespace Genbox.FastCodeSign.Enums;

[Flags]
public enum SignatureComponent : byte
{
    None = 0,
    CodeResourcesFile = 1,
    LegacyCodeResourcesFile = 2,
    CodeSignatureFolder = 4,
    MachObjectSignature = 8
}