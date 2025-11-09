using System.Text;
using Genbox.FastCodeSign.Internal.MachObject;

namespace Genbox.FastCodeSign.Tests;

public class PListSerializerTests
{
    [Theory]
    [InlineData("Discord-CodeResources.dat")]
    [InlineData("Discord-Info.dat")]
    private async Task Deserialize(string resourceName)
    {
        Dictionary<string, object> obj = PListSerializer.Deserialize(await File.ReadAllBytesAsync("Resources/" + resourceName));
        Assert.NotNull(obj);

        await Verify(obj)
              .UseFileName($"{nameof(Deserialize)}-{resourceName}")
              .UseDirectory("Verify/" + nameof(PListSerializerTests))
              .DisableDiff();
    }

    [Fact]
    private async Task SerializeAndDeserialize()
    {
        using MemoryStream ms = new MemoryStream();
        PListSerializer.Serialize(new Dictionary<string, object>
        {
            { "string-test", "asd" }, // String support
            { "bool-test", true },
            { "float-test", 1.0f },
            { "double-test", 1.0d },
            { "byte-array-test", new byte[] { 1, 2, 3, 4 } },
            { "string-array-test", new[] { "string1", "string2" } },
            {
                "dict-test", new Dictionary<string, object>
                {
                    { "sub-dict-string-test", "value" },
                    { "sub-dict-bool-test", true }
                }
            }
        }, ms);

        byte[] data = ms.ToArray();

        await Verify(Encoding.UTF8.GetString(data))
              .UseFileName($"{nameof(SerializeAndDeserialize)}-Serialized")
              .UseDirectory("Verify/" + nameof(PListSerializerTests))
              .DisableDiff();

        Dictionary<string, object> dict = PListSerializer.Deserialize(data);

        await Verify(dict)
              .UseFileName($"{nameof(SerializeAndDeserialize)}-Deserialized")
              .UseDirectory("Verify/" + nameof(PListSerializerTests))
              .DisableDiff();
    }
}