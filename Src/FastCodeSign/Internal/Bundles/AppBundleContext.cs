using Genbox.FastCodeSign.Abstracts;
using Genbox.FastCodeSign.Allocations;
using Genbox.FastCodeSign.Handlers;
using Genbox.FastCodeSign.Helpers;
using Genbox.FastCodeSign.Internal.Helpers;
using Genbox.FastCodeSign.Internal.MachObject;

namespace Genbox.FastCodeSign.Internal.Bundles;

public class AppBundleContext : IContext
{
    public required string Identifier { get; init; }
    public required bool HasResources { get; init; }
    public required string BundlePath { get; init; }
    public required string BundleExecutablePath { get; init; }
    public bool IsSigned { get; private init; }

    public static AppBundleContext Create(string bundlePath)
    {
        string fullBundlePath = Path.GetFullPath(bundlePath);
        if (PathHelper.IsReparsePoint(fullBundlePath))
            throw new IOException("Signing a bundle through a symbolic link or reparse point is not supported.");

        string contents = Path.Combine(fullBundlePath, "Contents");

        if (!Directory.Exists(contents))
            throw new DirectoryNotFoundException("Content directory not found");

        if (!PathHelper.IsPhysicalPathWithin(contents, fullBundlePath))
            throw new InvalidDataException("The bundle Contents directory resolves outside the bundle.");

        string plist = Path.Combine(contents, "Info.plist");

        if (!File.Exists(plist))
            throw new FileNotFoundException("Info.plist file not found");

        (string executable, string identifier) = GetBundleInfo(plist);
        if (!IsSimpleFileName(executable))
            throw new InvalidDataException("CFBundleExecutable must be a simple filename.");

        string macOsPath = Path.GetFullPath(Path.Combine(contents, "MacOS"));
        string bundleExecutablePath = Path.GetFullPath(Path.Combine(macOsPath, executable));

        if (!File.Exists(bundleExecutablePath))
            throw new FileNotFoundException("Main bundle executable file not found");

        if (!PathHelper.IsPhysicalPathWithin(bundleExecutablePath, fullBundlePath))
            throw new InvalidDataException("CFBundleExecutable resolves outside the bundle.");

        bool isSigned = File.Exists(Path.Combine(contents, "_CodeSignature", "CodeResources")) || File.Exists(Path.Combine(contents, "CodeResources"));

        using (FileAllocation file = new FileAllocation(bundleExecutablePath))
        {
            Span<byte> span = file.GetSpan();
            Models.MachObject[] objs = MachObjectHelper.GetMachObjects(span);

            if (objs.Length == 0)
                throw new InvalidDataException("Unable to find a valid mach object");

            IFormatHandler handler = new MachObjectFormatHandler();
            foreach (Models.MachObject fatObject in objs)
                isSigned |= handler.GetContext(fatObject.GetSpan(span)).IsSigned;
        }

        return new AppBundleContext
        {
            Identifier = identifier,
            HasResources = Directory.Exists(Path.Combine(contents, "Resources")),
            BundlePath = fullBundlePath,
            BundleExecutablePath = bundleExecutablePath,
            IsSigned = isSigned
        };
    }

    private static (string executable, string identifier) GetBundleInfo(string pListFile)
    {
        Dictionary<string, object> pList = PListSerializer.Deserialize(File.ReadAllBytes(pListFile));

        if (!pList.TryGetValue("CFBundleExecutable", out object? bundleExec))
            throw new InvalidDataException("CFBundleExecutable was not found");

        if (!pList.TryGetValue("CFBundleIdentifier", out object? bundleIdent))
            throw new InvalidDataException("CFBundleIdentifier was not found");

        return ((string)bundleExec, (string)bundleIdent);
    }

    private static bool IsSimpleFileName(string value) => value.Length != 0 && !Path.IsPathRooted(value) && value.IndexOf('/', StringComparison.Ordinal) < 0 && value.IndexOf('\\', StringComparison.Ordinal) < 0 && value != "." && value != "..";
}