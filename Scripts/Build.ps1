$Config = "Debug"
$Root = (Resolve-Path "$PSScriptRoot/..").Path

dotnet build $Root/FastCodeSignature.sln -c $Config
