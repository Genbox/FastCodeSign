using Genbox.FastCodeSign.Abstracts;
using Genbox.FastCodeSign.Allocations;
using Genbox.FastCodeSign.Handlers;
using Genbox.FastCodeSign.Helpers;
using Genbox.FastCodeSign.Internal.MachObject;

namespace Genbox.FastCodeSign.Internal.Bundles;

public class AppBundleContext : IContext
{
    public static AppBundleContext Create(string bundlePath)
    {
        string contents = Path.Combine(bundlePath, "Contents");

        if (!Directory.Exists(contents))
            throw new DirectoryNotFoundException("Content directory not found");

        string plist = Path.Combine(contents, "Info.plist");

        if (!File.Exists(plist))
            throw new FileNotFoundException("Info.plist file not found");

        (string executable, string identifier) = GetBundleInfo(plist);
        string bundleExecutablePath = Path.Combine(contents, "MacOS", executable);

        if (!File.Exists(bundleExecutablePath))
            throw new FileNotFoundException("Main bundle executable file not found");

        // Check if there is a CodeResources file first
        bool isSigned = File.Exists(Path.Combine(contents, "_CodeSignature", "CodeResources"));

        if (isSigned)
        {
            // Read each of the mach objects and determine if they are signed
            using FileAllocation file = new FileAllocation(bundleExecutablePath);
            Span<byte> span = file.GetSpan();

            // The mach object can be a FAT file, so we wrap the handling in this helper
            Models.MachObject[] objs = MachObjectHelper.GetMachObjects(span);

            if (objs.Length == 0)
                throw new InvalidDataException("Unable to find a valid mach object");

            IFormatHandler handler = new MachObjectFormatHandler();

            // Each mach object must be signed too
            foreach (Models.MachObject fatObject in objs)
                isSigned &= handler.GetContext(fatObject.GetSpan(span)).IsSigned;
        }

        return new AppBundleContext
        {
            Identifier = identifier,
            HasResources = Directory.Exists(Path.Combine(contents, "Resources")),
            BundlePath = bundlePath,
            BundleExecutablePath = bundleExecutablePath,
            IsSigned = isSigned
        };
    }

    public required string Identifier { get; init; }
    public required bool HasResources { get; init; }
    public required string BundlePath { get; init; }
    public required string BundleExecutablePath { get; init; }
    public bool IsSigned { get; private init; }

    private static (string executable, string identifier) GetBundleInfo(string pListFile)
    {
        Dictionary<string, object> pList = PListSerializer.Deserialize(File.ReadAllBytes(pListFile));

        if (!pList.TryGetValue("CFBundleExecutable", out object? bundleExec))
            throw new InvalidDataException("CFBundleExecutable was not found");

        if (!pList.TryGetValue("CFBundleIdentifier", out object? bundleIdent))
            throw new InvalidDataException("CFBundleIdentifier was not found");

        return ((string)bundleExec, (string)bundleIdent);
    }
}