using System.Diagnostics.CodeAnalysis;
using System.IO.MemoryMappedFiles;
using Genbox.FastCodeSign.Abstracts;

namespace Genbox.FastCodeSign.Allocations;

[SuppressMessage("IDisposableAnalyzers.Correctness", "IDISP023:Don\'t use reference types in finalizer context")]
[SuppressMessage("IDisposableAnalyzers.Correctness", "IDISP003:Dispose previous before re-assigning")]
public sealed class FileAllocation : IAllocation, IDisposable
{
    private readonly bool _canWrite;
    private readonly FileStream _fileStream;
    private MemoryMappedFile? _mmf;
    private unsafe byte* _ptr;
    private MemoryMappedViewAccessor? _view;

    public FileAllocation(string filePath)
    {
        FilePath = filePath;

        try
        {
            _fileStream = new FileStream(filePath, FileMode.Open, FileAccess.ReadWrite);
            _canWrite = true;
        }
        catch (UnauthorizedAccessException)
        {
            _fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            _canWrite = false;
        }

        CreateProvider();
    }

    public string FilePath { get; }

    public unsafe Span<byte> GetSpan()
    {
        if (_view == null)
            return Span<byte>.Empty;

        int length = (int)_view.Capacity;
        return new Span<byte>(_ptr, length);
    }

    public void SetLength(uint length)
    {
        if (!_canWrite)
            throw new UnauthorizedAccessException("The file was opened read-only and cannot be resized.");

        Dispose(false);

        _fileStream.SetLength(length);

        CreateProvider();
    }

    public void Dispose() => Dispose(true);

    private unsafe void CreateProvider()
    {
        if (_fileStream.Length == 0)
            return;

        MemoryMappedFileAccess access = _canWrite ? MemoryMappedFileAccess.ReadWrite : MemoryMappedFileAccess.Read;
        _mmf = MemoryMappedFile.CreateFromFile(_fileStream, null, _fileStream.Length, access, HandleInheritability.None, true);
        _view = _mmf.CreateViewAccessor(0, _fileStream.Length, access);

        _view.SafeMemoryMappedViewHandle.AcquirePointer(ref _ptr);
    }

    private unsafe void Dispose(bool all)
    {
        if (_view != null)
        {
            if (_canWrite)
                _view.Flush();

            _view.SafeMemoryMappedViewHandle.ReleasePointer();
            _view.Dispose();
            _view = null;
        }

        _ptr = null;

        _mmf?.Dispose();
        _mmf = null;

        if (all)
            _fileStream.Dispose();
    }
}