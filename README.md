# FastCodeSign

[![NuGet](https://img.shields.io/nuget/v/Genbox.FastCodeSign.svg?style=flat-square&label=nuget)](https://www.nuget.org/packages/Genbox.FastCodeSign/)
[![License](https://img.shields.io/github/license/Genbox/FastCodeSign)](https://github.com/Genbox/FastCodeSign/blob/main/LICENSE.txt)

### Description

A cross-platform code signing library for Windows Authenticode, PowerShell and macOS code signatures.
Has no external dependencies. Written with performance in mind. Has a simple one-shot API that auto-detects file format.

### Features

* Supports signing Windows executables, PowerShell scripts and macOS macho files
* Supports signing blobs in memory with no intermediate files
* Supports hardware security module (HSM) through key operation delegation:
    * Windows: [Cryptographic Next Generation](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal?redirectedfrom=MSDN)
    * macOS: [Apple Security Framework](https://developer.apple.com/documentation/Security)
    * Linux: [OpenSSL](https://www.openssl.org/)
    * Custom: Implement the [AsymmetricAlgorithm](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.asymmetricalgorithm?view=net-9.0) class
* Zero-copy `Span<T>` based APIs

### Example

```csharp
internal static class Program
{
    private static void Main()
    {
        byte[] pwsh = """
                      Write-Host "Hello world!"
                      """u8.ToArray();

        // You need to provide a code signing certificate
        X509Certificate2 cert = X509CertificateLoader.LoadPkcs12FromFile("FastCodeSign.pfx", "password");

        // We set the filename, only to make it easier for the file format detection to select the right signer
        Span<byte> signed = CodeSign.SignData(pwsh, cert, fileName: "script.ps1");
        Console.WriteLine(Encoding.UTF8.GetString(signed));
    }
}
```

Output:

```
Write-Host "Hello world!"
# SIG # Begin signature block
# MIIIiwYJKoZIhvcNAQcCoIIIfDCCCHgCAQMxDTALBglghkgBZQMEAgEwewYKKwYB
# BAGCNwIBBKBtBGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# <truncated for brevity>
# X59J9Shad7x2+oeU+7bRggn6aqJXcUeA36zmMcY8VwesOTRDth06bD4QzoP3uOSm
# tKO4SXHci/UEJNK/0fYOUcI1pBm6hgY/5tG/pBwVLrPhOhFw3OTpfFrkAldNCAn7
# uFlJfKDOoPk39t3kA7d+/A1Nj++kn2UaF1GLfId6Gw==
# SIG # End signature block
```

### Filetype support

#### Authenticode

Windows portable executables:

* exe: Windows Portable Executable files
* dll: Windows Dynamic Link Library files
* sys: Windows System files
* scr; Windows Screensaver files
* ocx: Windows ActiveX control files
* cpl: Windows Control Panel applet files
* mun: Windows resource-only files
* mui: Windows language resource files
* drv: Windows driver files
* winmd: Windows Runtime Metadata files
* ax: Windows DirectShow filters
* efi: UEFI application/driver files

PowerShell files:

* ps1: PowerShell script files
* psm1: PowerShell module files
* psd1: PowerShell data files
* ps1xml: PowerShell XML files
* psc1: PowerShell Console files
* cdxml: PowerShell cmdlet definition XML files

#### macOS code sign

* Mach Object files

#### Not supported

* dmg/pkg/app: Bundle files for macOS
* cat: Catalog Security file
* manifest: Application manifest file
* application: ClickOnce deployment manifest file
* xap: Silverlight Application file
* msi: Windows Installer file
* cab: Windows Cabinet file