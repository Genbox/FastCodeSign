using Genbox.FastCodeSignature.Abstracts;
using Genbox.FastCodeSignature.Allocations;

namespace Genbox.FastCodeSignature;

public sealed class CodeSignFileProvider : CodeSignProvider, IDisposable
{
    private readonly FileAllocation _allocation;

    internal CodeSignFileProvider(IFormatHandler handler, FileAllocation allocation) : base(handler, allocation)
    {
        _allocation = allocation;
    }

    public void Dispose() => _allocation.Dispose();
}