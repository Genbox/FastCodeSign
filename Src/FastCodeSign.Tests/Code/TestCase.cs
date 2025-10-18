using Genbox.FastCodeSign.Abstracts;
using JetBrains.Annotations;
using Xunit.Sdk;

namespace Genbox.FastCodeSign.Tests.Code;

internal sealed class TestCase : IXunitSerializable
{
    private string _id = "";

    [UsedImplicitly]
    public TestCase() {}

    private TestCase(Func<IAllocation, CodeSignProvider> factory, Type handlerType, string signedFile, string unsignedFile, string hash, Action<Span<byte>>? equalityPatch)
    {
        Factory = factory;
        SignedFile = signedFile;
        UnsignedFile = unsignedFile;
        Hash = hash;
        EqualityPatch = equalityPatch;

        _id = handlerType.Name + " " + SignedFile;
    }

    public Action<Span<byte>>? EqualityPatch { get; }
    public Func<IAllocation, CodeSignProvider> Factory { get; } = null!;
    public string SignedFile { get; } = null!;
    public string UnsignedFile { get; } = null!;
    public string Hash { get; } = null!;

    public static TestCase Create(IFormatHandler handler, string signed, string unsigned, string hash, Action<Span<byte>>? equalityPatch = null)
    {
        return new TestCase(x => new CodeSignProvider(handler, x), handler.GetType(), Path.Combine(Constants.FilesDir, signed), Path.Combine(Constants.FilesDir, unsigned), hash, equalityPatch);
    }

    public void Deserialize(IXunitSerializationInfo info) => _id = info.GetValue<string>(nameof(_id))!;
    public void Serialize(IXunitSerializationInfo info) => info.AddValue(nameof(_id), _id);

    public override string ToString()
    {
        string fileName = Path.GetFileName(SignedFile);

        //If there is one underscore, we show the entire filename
        if (fileName.Count(x => x == '_') == 1)
            return fileName;

        return fileName[..fileName.LastIndexOf('_')];
    }
}