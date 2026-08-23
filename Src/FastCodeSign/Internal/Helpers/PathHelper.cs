namespace Genbox.FastCodeSign.Internal.Helpers;

internal static class PathHelper
{
    internal static string? GetExt(string fileName)
    {
        // DPR-004: Only treat the final path segment's extension as a type hint; dotfiles like ".env" have no extension.
        string ext = Path.GetExtension(fileName);
        return ext.Length <= 1 ? null : ext[1..].ToLowerInvariant();
    }

    internal static bool IsReparsePoint(string path) => (File.GetAttributes(path) & FileAttributes.ReparsePoint) != FileAttributes.None;

    internal static bool IsPhysicalPathWithin(string candidate, string root)
    {
        string physicalCandidate = ResolvePhysicalPath(candidate);
        string physicalRoot = Path.TrimEndingDirectorySeparator(ResolvePhysicalPath(root));
        StringComparison comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        return string.Equals(physicalCandidate, physicalRoot, comparison) || physicalCandidate.StartsWith(physicalRoot + Path.DirectorySeparatorChar, comparison);
    }

    private static string ResolvePhysicalPath(string path)
    {
        string fullPath = Path.GetFullPath(path);
        string root = Path.GetPathRoot(fullPath) ?? throw new InvalidDataException($"Path '{path}' does not have a root.");
        string current = root;
        string relative = Path.GetRelativePath(root, fullPath);

        foreach (string component in relative.Split([Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar], StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, component);
            FileAttributes attributes = File.GetAttributes(current);
            if ((attributes & FileAttributes.ReparsePoint) == FileAttributes.None)
                continue;

            FileSystemInfo info = (attributes & FileAttributes.Directory) != FileAttributes.None ? new DirectoryInfo(current) : new FileInfo(current);
            current = info.ResolveLinkTarget(true)?.FullName ?? throw new IOException($"Unable to resolve symbolic link '{current}'.");
        }

        return Path.TrimEndingDirectorySeparator(Path.GetFullPath(current));
    }
}