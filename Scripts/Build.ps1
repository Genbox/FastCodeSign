$Config = "Debug"
$Root = (Resolve-Path "$PSScriptRoot/..").Path

dotnet build $Root/FastCodeSign.sln -c $Config
