namespace Genbox.FastCodeSignature.Internal.Native.Enums;

//https://learn.microsoft.com/en-us/windows/win32/seccrypto/signer-subject-info
internal enum SIGNER_SUBJECT : uint
{
    SIGNER_SUBJECT_FILE = 1,
    SIGNER_SUBJECT_BLOB = 2
}