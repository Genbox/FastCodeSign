using Genbox.FastCodeSign.Abstracts;

namespace Genbox.FastCodeSign.Allocations;

//TODO: Need a more efficient way of working with memory blobs

public sealed class MemoryAllocation(Memory<byte> data) : IAllocation
{
    private Memory<byte> _data = data; //We keep this field because we ref it in SetLength()

    public Span<byte> GetSpan() => _data.Span;

    public void SetLength(uint length)
    {
        byte[] newArr = new byte[length];

        int copyLen = (int)Math.Min(length, _data.Length);

        _data[..copyLen].CopyTo(newArr);
        _data = newArr;
    }
}