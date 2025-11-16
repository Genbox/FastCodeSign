using Genbox.FastCodeSign.Abstracts;

namespace Genbox.FastCodeSign.Tests.Code;

internal sealed class TestCase : XUnitTest
{
    private TestCase(Func<IAllocation, CodeSignProvider> providerFactory, Type handlerType, string signed, string unsigned, string hash, Action<Span<byte>>? equalityPatch, IFormatOptions? formatOptions) : base(handlerType.Name + " " + signed)
    {
        ProviderFactory = providerFactory;
        FormatOptions = formatOptions;
        Signed = signed;
        Unsigned = unsigned;
        Hash = hash;
        EqualityPatch = equalityPatch;
    }

    public Action<Span<byte>>? EqualityPatch { get; }
    public Func<IAllocation, CodeSignProvider> ProviderFactory { get; }
    public IFormatOptions? FormatOptions { get; }
    public string Signed { get; }
    public string Unsigned { get; }
    public string Hash { get; }

    public static TestCase Create(IFormatHandler handler, string signed, string unsigned, string hash, IFormatOptions? formatOptions = null, Action<Span<byte>>? equalityPatch = null)
    {
        return new TestCase(
            x => new CodeSignProvider(handler, x),
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
        if (fileName.Count(x => x == '_') == 1)
            return fileName;

        return fileName[..fileName.LastIndexOf('_')];
    }
}