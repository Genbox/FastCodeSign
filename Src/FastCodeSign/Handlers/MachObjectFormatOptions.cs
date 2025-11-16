using Genbox.FastCodeSign.Abstracts;
using Genbox.FastCodeSign.MachObjects;

namespace Genbox.FastCodeSign.Handlers;

public class MachObjectFormatOptions : IFormatOptions
{
    /// <summary>
    /// The identifier to use. By default, macOS codesign uses the filename of the file.
    /// </summary>
    public required string Identifier { get; init; }

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
}