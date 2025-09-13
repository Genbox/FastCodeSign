$pfxPath = Join-Path $PSScriptRoot "../Files/FastCodeSignature.pfx"

$cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject 'CN=FastCodeSignature' `
    -FriendlyName 'FastCodeSignature' `
    -KeyAlgorithm RSA `
    -KeyLength 4096 `
    -HashAlgorithm SHA256 `
    -KeyUsage DigitalSignature `
    -KeySpec Signature `
    -KeyExportPolicy Exportable `
    -NotAfter (Get-Date).AddYears(3) `
    -CertStoreLocation 'Cert:\CurrentUser\My'

# Export the certificate with its private key to a PFX file
$pwd = ConvertTo-SecureString -String "password" -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $pwd

# Remove cert from store so only the PFX file remains
Remove-Item -Path "Cert:\CurrentUser\My\$( $cert.Thumbprint )" -Force