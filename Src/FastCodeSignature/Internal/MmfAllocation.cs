using System.Diagnostics.CodeAnalysis;
using System.IO.MemoryMappedFiles;
using Genbox.FastCodeSignature.Abstracts;

namespace Genbox.FastCodeSignature.Internal;

[SuppressMessage("IDisposableAnalyzers.Correctness", "IDISP023:Don\'t use reference types in finalizer context")]
[SuppressMessage("IDisposableAnalyzers.Correctness", "IDISP003:Dispose previous before re-assigning")]
internal sealed class MmfAllocation : IAllocation
{
    private readonly FileStream _fileStream;
    private MemoryMappedFile _mmf;
    private unsafe byte* _ptr;
    private MemoryMappedViewAccessor _view;

    public MmfAllocation(string file)
    {
        _fileStream = new FileStream(file, FileMode.Open, FileAccess.ReadWrite);
        CreateProvider();
    }

    public unsafe Span<byte> GetSpan()
    {
        int length = (int)_view.Capacity;
        return new Span<byte>(_ptr, length);
    }

    public void SetLength(uint length)
    {
        Dispose(false);

        _fileStream.SetLength(length);

        CreateProvider();
    }

    public void Dispose() => Dispose(true);

    private unsafe void CreateProvider()
    {
        _mmf = MemoryMappedFile.CreateFromFile(_fileStream, null, _fileStream.Length, MemoryMappedFileAccess.ReadWrite, HandleInheritability.None, true);
        _view = _mmf.CreateViewAccessor(0, _fileStream.Length, MemoryMappedFileAccess.ReadWrite);

        _view.SafeMemoryMappedViewHandle.AcquirePointer(ref _ptr);
    }

    private unsafe void Dispose(bool all)
    {
        _view.Flush();

        _view.SafeMemoryMappedViewHandle.ReleasePointer();
        _view.Dispose();

        _ptr = null;

        _mmf.Dispose();

        if (all)
            _fileStream.Dispose();
    }
}