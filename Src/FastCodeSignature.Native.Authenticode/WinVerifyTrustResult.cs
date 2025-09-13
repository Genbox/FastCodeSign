namespace Genbox.FastCodeSignature.Native.Authenticode;

public enum WinVerifyTrustResult : uint
{
    SUCCESS = 0,

    /// <summary>Trust provider is not recognized on this system</summary>
    TRUST_E_SYSTEM_ERROR = 0x80096001,

    /// <summary>Trust provider does not support the specified action</summary>
    TRUST_E_NO_SIGNER_CERT = 0x80096002,

    /// <summary>Trust provider does not support the form specified for the subject</summary>
    TRUST_E_COUNTER_SIGNER = 0x80096003,

    /// <summary>The signature of the certificate can not be verified.</summary>
    TRUST_E_CERT_SIGNATURE = 0x80096004,
    TRUST_E_TIME_STAMP = 0x80096005,

    /// <summary>File was probably corrupt</summary>
    TRUST_E_BAD_DIGEST = 0x80096010,

    /// <summary>A certificate's basic constraint extension has not been observed.</summary>
    TRUST_E_BASIC_CONSTRAINTS = 0x80096019,

    /// <summary>The certificate does not meet or contain the Authenticode(tm) financial extensions.</summary>
    TRUST_E_FINANCIAL_CRITERIA = 0x8009601E,

    /// <summary>Trust provider is not recognized on this system</summary>
    TRUST_E_PROVIDER_UNKNOWN = 0x800B0001,

    /// <summary>Trust provider does not support the specified action</summary>
    TRUST_E_ACTION_UNKNOWN = 0x800B0002,

    /// <summary>Trust provider does not support the form specified for the subject</summary>
    TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0003,

    /// <summary>Subject failed the specified verification action</summary>
    TRUST_E_SUBJECT_NOT_TRUSTED = 0x800B0004,

    /// <summary>File was not signed</summary>
    TRUST_E_NOSIGNATURE = 0x800B0100,

    /// <summary>A required certificate is not within its validity period when verifying against the current system clock or the timestamp in the signed file.</summary>
    CERT_E_EXPIRED = 0x800B0101,

    /// <summary>The validity periods of the certification chain do not nest correctly.</summary>
    CERT_E_VALIDITYPERIODNESTING = 0x800B0102,

    /// <summary>A certificate chain processed, but terminated in a root certificate which is not trusted by the trust provider.</summary>
    CERT_E_UNTRUSTEDROOT = 0x800B0109,

    /// <summary>An internal certificate chaining error has occurred.</summary>
    CERT_E_CHAINING = 0x800B010A,

    /// <summary>Generic trust failure.</summary>
    TRUST_E_FAIL = 0x800B010B,

    /// <summary>A certificate was explicitly revoked by its issuer.</summary>
    CERT_E_REVOKED = 0x800B010C,

    /// <summary>The certification path terminates with the test root which is not trusted with the current policy settings.</summary>
    CERT_E_UNTRUSTEDTESTROOT = 0x800B010D,

    /// <summary>The revocation process could not continue - the certificate(s) could not be checked.</summary>
    CERT_E_REVOCATION_FAILURE = 0x800B010E,

    /// <summary>The certificate is not valid for the requested usage.</summary>
    CERT_E_WRONG_USAGE = 0x800B0110,

    /// <summary>Signer's certificate is in the Untrusted Publishers store</summary>
    TRUST_E_EXPLICIT_DISTRUST = 0x800B0111,

    /// <summary>The certificate has invalid policy.</summary>
    CERT_E_INVALID_POLICY = 0x800B0113,

    /// <summary>The certificate has an invalid name. The name is not included in the permitted list or is explicitly excluded.</summary>
    CERT_E_INVALID_NAME = 0x800B0114,

    FILE_NOT_FOUND = 0x80092003
}