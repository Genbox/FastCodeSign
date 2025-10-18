namespace Genbox.FastCodeSign.Internal.Native.Enums;

//https://learn.microsoft.com/en-us/windows/win32/seccrypto/signer-cert-store-info
[Flags]
internal enum SIGNER_CERT_POLICY
{
    SIGNER_CERT_POLICY_STORE = 1,
    SIGNER_CERT_POLICY_CHAIN = 2,
    SIGNER_CERT_POLICY_CHAIN_NO_ROOT = 8
}