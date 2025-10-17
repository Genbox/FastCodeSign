namespace Genbox.FastCodeSignature.Internal.Helpers;

internal static class PathHelper
{
    internal static string? GetExt(string fileName)
    {
        int idx = fileName.LastIndexOf('.');
        return idx == -1 ? null : fileName[(idx + 1)..].ToLowerInvariant();
    }
}