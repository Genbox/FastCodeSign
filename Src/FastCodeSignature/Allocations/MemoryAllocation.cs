using Genbox.FastCodeSignature.Abstracts;

namespace Genbox.FastCodeSignature.Allocations;

public sealed class MemoryAllocation(Memory<byte> data) : IAllocation
{
    private Memory<byte>? _ext;
    private Memory<byte> _data = data;

    public Span<byte> GetData() => _data.Span;

    public Span<byte> CreateExtension(uint size)
    {
        if (_ext != null)
            throw new InvalidOperationException("Extension already exists");

        byte[] ext = new byte[size];
        _ext = new Memory<byte>(ext);
        return ext;
    }

    public Span<byte> GetExtension()
    {
        ArgumentNullException.ThrowIfNull(_ext);
        return _ext.Value.Span;
    }

    public void TruncateDataTo(uint newLength) => _data = _data[..(int)newLength];
}