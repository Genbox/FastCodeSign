namespace Genbox.FastCodeSign.Enums;

/// <summary>Controls how signing handles an existing signature.</summary>
public enum ExistingSignatureBehavior
{
    /// <summary>Reject files and bundles that already contain a signature.</summary>
    Fail,
    /// <summary>Remove the existing signature before creating a replacement signature.</summary>
    Replace
}