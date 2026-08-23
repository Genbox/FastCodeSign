namespace Genbox.FastCodeSign.MachObjects;

/// <summary>
/// Controls macOS code-signing behavior for Mach-O executables.
/// </summary>
[Flags]
public enum MachObjectSigningFlags
{
    None = 0,

    /// <summary>
    /// Enables the macOS hardened runtime.
    /// </summary>
    HardenedRuntime = 1
}