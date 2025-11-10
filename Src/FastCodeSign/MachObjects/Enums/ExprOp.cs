namespace Genbox.FastCodeSign.MachObjects.Enums;

// https://github.com/apple-oss-distributions/Security/blob/3dab46a11f45f2ffdbd70e2127cc5a8ce4a1f222/OSX/libsecurity_codesigning/lib/requirement.h#L160
public enum ExprOp
{
    False, // unconditionally false
    True, // unconditionally true
    Ident, // match canonical code [string]
    AppleAnchor, // signed by Apple as Apple's product
    AnchorHash, // match anchor [cert hash]
    InfoKeyValue, // *legacy* - use opInfoKeyField [key; value]
    And, // binary prefix expr AND expr [expr; expr]
    Or, // binary prefix expr OR expr [expr; expr]
    CdHash, // match hash of CodeDirectory directly [cd hash]
    Not, // logical inverse [expr]
    InfoKeyField, // Info.plist key field [string; match suffix]
    CertField, // Certificate field, existence only [cert index; field name; match suffix]
    TrustedCert, // require trust settings to approve one particular cert [cert index]
    TrustedCerts, // require trust settings to approve the cert chain
    CertGeneric, // Certificate component by OID [cert index; oid; match suffix]
    AppleGenericAnchor, // signed by Apple in any capacity
    EntitlementField, // entitlement dictionary field [string; match suffix]
    CertPolicy, // Certificate policy by OID [cert index; oid; match suffix]
    NamedAnchor, // named anchor type
    NamedCode, // named subroutine
    Platform, // platform constraint [integer]
    Notarized, // has a developer id+ ticket
    CertFieldDate, // extension value as timestamp [cert index; field name; match suffix]
    LegacyDevId // meets legacy (pre-notarization required) policy
}