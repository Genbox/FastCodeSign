using Genbox.FastCodeSign.Abstracts;
using Genbox.FastCodeSign.MachObjects;

namespace Genbox.FastCodeSign.BundleHandlers;

public class AppBundleOptions : IBundleOptions
{
    /// <summary>
    /// The requirements to embed into the signature. Set to null to use macOS defaults.
    /// </summary>
    public Requirements? Requirements { get; set; }

    /// <summary>
    /// The entitlements to embed into the signature.
    /// </summary>
    public Entitlements? Entitlements { get; set; }

    /// <summary>
    /// The resource seal to embed into the signature.
    /// </summary>
    public Dictionary<string, object>? ResourcesPropertyList { get; set; }

    /// <summary>
    /// The property list to embed into the signature.
    /// </summary>
    public Dictionary<string, object>? InfoPropertyList { get; set; }

    /// <summary>
    /// An optional team id.
    /// </summary>
    public string? TeamId { get; set; }

    /// <summary>
    /// Controls macOS code-signing behavior for the bundle executable and nested code.
    /// </summary>
    public MachObjectSigningFlags SigningFlags { get; set; }
}