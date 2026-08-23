using Genbox.FastCodeSign.Abstracts;

namespace Genbox.FastCodeSign.Tests.Code;

internal sealed class TestCase : XUnitTest
{
    public TestCase()
    {
        ProviderFactory = _ => throw new InvalidOperationException("This test case was not initialized.");
        Signed = string.Empty;
        Unsigned = string.Empty;
        Hash = string.Empty;
        HandlerType = typeof(void);
    }

    private TestCase(Func<IAllocation, CodeSignProvider> providerFactory, Type handlerType, string signed, string unsigned, string hash, Action<Span<byte>>? equalityPatch, IFormatOptions? formatOptions) : base(handlerType.Name + " " + signed)
    {
        ProviderFactory = providerFactory;
        FormatOptions = formatOptions;
        Signed = signed;
        Unsigned = unsigned;
        Hash = hash;
        EqualityPatch = equalityPatch;
        HandlerType = handlerType;
    }

    public Action<Span<byte>>? EqualityPatch { get; }
    public Func<IAllocation, CodeSignProvider> ProviderFactory { get; }
    public IFormatOptions? FormatOptions { get; }
    public string Signed { get; }
    public string Unsigned { get; }
    public string Hash { get; }
    public Type HandlerType { get; }

    public static TestCase Create(IFormatHandler handler, string signed, string unsigned, string hash, IFormatOptions? formatOptions = null, Action<Span<byte>>? equalityPatch = null)
    {
        return new TestCase(
            x => new CodeSignProvider(handler, x, Path.GetFileName(unsigned)),
            handler.GetType(),
            Path.Combine(Constants.FilesDir, signed),
            Path.Combine(Constants.FilesDir, unsigned),
            hash,
            equalityPatch,
            formatOptions
        );
    }

    public override string ToString()
    {
        string fileName = Path.GetFileName(Signed);

        //If there is one underscore, we show the entire filename
        if (fileName.IndexOf('_') >= 0 && fileName.IndexOf('_') == fileName.LastIndexOf('_'))
            return fileName;

        return fileName[..fileName.LastIndexOf('_')];
    }
}