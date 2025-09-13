using System.Runtime.CompilerServices;
using VerifyTests.DiffPlex;

namespace Genbox.FastCodeSignature.Native.Authenticode.Tests.Properties;

internal static class ModuleInitializer
{
    [ModuleInitializer]
    public static void Initialize() => VerifyDiffPlex.Initialize(OutputType.Compact);
}