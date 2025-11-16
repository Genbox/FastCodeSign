using Genbox.FastCodeSign.Abstracts;
using Genbox.FastCodeSign.Allocations;

namespace Genbox.FastCodeSign;

public sealed class CodeSignFileProvider : CodeSignProvider, IDisposable
{
    private readonly FileAllocation _allocation;

    internal CodeSignFileProvider(IFormatHandler handler, FileAllocation allocation, string fileName) : base(handler, allocation, fileName)
    {
        _allocation = allocation;
    }

    public void Dispose() => _allocation.Dispose();
}