# FastCodeSign

[![NuGet](https://img.shields.io/nuget/v/Genbox.FastCodeSign.svg?style=flat-square&label=nuget)](https://www.nuget.org/packages/Genbox.FastCodeSign/)
[![License](https://img.shields.io/github/license/Genbox/FastCodeSign)](https://github.com/Genbox/FastCodeSign/blob/main/LICENSE.txt)

### Description
A cross-platform code signing library for Windows Authenticode, PowerShell and macOS code signatures.

### Features

Supports signing the following portable executables:
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

Supports signing the following PowerShell files:
* ps1: PowerShell script files
* psm1: PowerShell module files
* psd1: PowerShell module manifest files
* ps1xml: PowerShell XML files
* psc1: PowerShell Console files
* cdxml: PowerShell cmdlet definition XML files

Supports signing these as well, but have not been tested:
* mof: Windows Management Instrumentation (WMI) Managed Object File (MOF)
* wsf: Windows Script File
* vbs: Visual Basic files
* js: JavaScript files

Not supported:
* cat: Catalog Security file
* manifest: Application manifest file
* application: ClickOnce deployment manifest file
* xap: Silverlight Application file
* msi: Windows Installer file
* cab: Windows Cabinet file