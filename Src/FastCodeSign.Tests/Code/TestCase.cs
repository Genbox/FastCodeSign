using Genbox.FastCodeSign.Abstracts;
using JetBrains.Annotations;
using Xunit.Sdk;

namespace Genbox.FastCodeSign.Tests.Code;

internal sealed class TestCase : XUnitTest
{
    [UsedImplicitly]
    public TestCase() : base("") {}

    private TestCase(Func<IAllocation, CodeSignProvider> providerFactory, Type handlerType, string signed, string unsigned, string hash, Action<Span<byte>>? equalityPatch) : base(handlerType.Name + " " + signed)
    {
        ProviderFactory = providerFactory;
        Signed = signed;
        Unsigned = unsigned;
        Hash = hash;
        EqualityPatch = equalityPatch;
    }

    public Action<Span<byte>>? EqualityPatch { get; }
    public Func<IAllocation, CodeSignProvider> ProviderFactory { get; } = null!;
    public string Signed { get; } = null!;
    public string Unsigned { get; } = null!;
    public string Hash { get; } = null!;

    public static TestCase Create(IFormatHandler handler, string signed, string unsigned, string hash, Action<Span<byte>>? equalityPatch = null)
    {
        return new TestCase(x => new CodeSignProvider(handler, x), handler.GetType(), Path.Combine(Constants.FilesDir, signed), Path.Combine(Constants.FilesDir, unsigned), hash, equalityPatch);
    }

    public override string ToString()
    {
        string fileName = Path.GetFileName(Signed);

        //If there is one underscore, we show the entire filename
        if (fileName.Count(x => x == '_') == 1)
            return fileName;

        return fileName[..fileName.LastIndexOf('_')];
    }
}