# Repository Guidelines

## Project Structure & Modules
- `Src/FastCodeSign`: Core cross-platform code signing library; targets Authenticode, Mach-O, and PowerShell.
- `Src/FastCodeSign.Native.Authenticode` (+ `.Tests`) and `Src/FastCodeSign.Native.MacCodeSign`: Native interop layers; keep platform-specific code here.
- `Src/FastCodeSign.Tests`: xUnit + Verify tests; snapshots live under `Src/FastCodeSign.Tests/Verify`.
- `Src/FastCodeSign.Examples` and `Src/FastCodeSign.Benchmarks`: Usage samples and performance runs; keep benchmarks local.
- Support folders: `Docs/` (format specs), `Scripts/` (build/publish automation), `Files/` (test fixtures), `Imports/` and `Locals/` (shared MSBuild settings).

## Build, Test, and Development Commands
- Restore/build: `dotnet restore` then `dotnet build FastCodeSign.sln` (respects `Directory.Build.*`).
- Run all tests: `dotnet test` (xUnit + Verify; outputs per project `bin/`).
- Targeted tests: `dotnet test --filter FullyQualifiedName~CodeSignTests` (or another class/trait).
- Benchmarks: `dotnet run --project Src/FastCodeSign.Benchmarks` (avoid in CI).

## Coding Style & Naming Conventions
- Language: C# with 4-space indentation and file-scoped namespaces; prefer `readonly` and `Span<T>/ReadOnlySpan<T>` patterns already in use.
- Naming: PascalCase for types/methods, camelCase for locals/parameters; keep constants obvious.
- Comments: Only for non-obvious parsing/crypto logic; favor self-explanatory code.
- Do not create newlines at EOF

## Testing Guidelines
- Frameworks: xUnit with Verify for snapshots; keep snapshots deterministic and stored in `Src/FastCodeSign.Tests/Verify`.
- Structure tests by feature/file; name with intent (e.g., `Signing_WithPasswordProtectedCert_Succeeds`).
- Always run `dotnet test` before pushing; add regression coverage for fixes and new APIs.

## Commit & Pull Request Guidelines
- Commits: Short, imperative summaries (e.g., “Add bundle signing”, “Rename FatObject to MachObject”); include scope if helpful.
- PRs: Explain motivation, key changes, and testing; link issues; note behavioral changes and doc/example updates when APIs shift.

## Security & Certificates
- Do not commit real certificates or secrets; use test fixtures in `Files/`.
- Prefer loading certificates from secure locations or environment-specific secrets; document any new config knobs in `Docs/`.
