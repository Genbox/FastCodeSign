using Xunit.Sdk;

namespace Genbox.FastCodeSign.Tests.Code;

internal abstract class XUnitTest(string id) : IXunitSerializable
{
    private string _id = id;
    public void Deserialize(IXunitSerializationInfo info) => _id = info.GetValue<string>(nameof(id))!;
    public void Serialize(IXunitSerializationInfo info) => info.AddValue(nameof(id), _id);
}