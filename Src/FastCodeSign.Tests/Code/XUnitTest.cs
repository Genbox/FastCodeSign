using Xunit.Sdk;

namespace Genbox.FastCodeSign.Tests.Code;

internal abstract class XUnitTest : IXunitSerializable
{
    private const string IdKey = "id";
    private string _id;

    protected XUnitTest() : this(string.Empty) {}

    protected XUnitTest(string id)
    {
        _id = id;
    }

    public void Deserialize(IXunitSerializationInfo info) => _id = info.GetValue<string>(IdKey)!;
    public void Serialize(IXunitSerializationInfo info) => info.AddValue(IdKey, _id);
}