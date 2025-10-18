using System.IO.MemoryMappedFiles;
using Genbox.FastCodeSignature.Abstracts;

namespace Genbox.FastCodeSignature.Allocations;

public sealed class FileAllocation : IAllocation, IDisposable
{
    private readonly FileStream _fileStream;
    private MemoryMappedFile _mmf;
    private MemoryMappedViewAccessor _dataView;
    private unsafe byte* _dataPtr;

    private MemoryMappedViewAccessor? _extView;
    private unsafe byte* _extPtr;

    public unsafe FileAllocation(string file)
    {
        _fileStream = new FileStream(file, FileMode.Open, FileAccess.ReadWrite);
        _mmf = MemoryMappedFile.CreateFromFile(_fileStream, null, _fileStream.Length, MemoryMappedFileAccess.ReadWrite, HandleInheritability.None, true);

        _dataView = _mmf.CreateViewAccessor(0, _fileStream.Length, MemoryMappedFileAccess.ReadWrite);
        _dataView.SafeMemoryMappedViewHandle.AcquirePointer(ref _dataPtr);
    }

    public void Dispose()
    {
        _dataView.Flush();
        _dataView.SafeMemoryMappedViewHandle.ReleasePointer();
        _dataView.Dispose();

        if (_extView != null)
        {
            _extView.Flush();
            _extView.SafeMemoryMappedViewHandle.ReleasePointer();
            _extView.Dispose();
        }

        _mmf.Dispose();
        _fileStream.Dispose();
    }

    public unsafe Span<byte> GetData()
    {
        int length = (int)_dataView.Capacity;
        return new Span<byte>(_dataPtr, length);
    }

    public unsafe Span<byte> CreateExtension(uint size)
    {
        if (_extView != null || _extPtr != null)
            throw new InvalidOperationException("Extension already created.");

        long oldLength = _fileStream.Length;
        long newLength = oldLength + size;

        // Extend the file with the new length
        _fileStream.SetLength(newLength);

        // We have to dispose the existing data view and memory mapped file to extend it with the new size
        _dataView.Flush();
        _dataView.SafeMemoryMappedViewHandle.ReleasePointer();
        _dataView.Dispose();
        _mmf.Dispose();

        _mmf = MemoryMappedFile.CreateFromFile(_fileStream, null, newLength, MemoryMappedFileAccess.ReadWrite, HandleInheritability.None, true);

        _dataView = _mmf.CreateViewAccessor(0, oldLength, MemoryMappedFileAccess.ReadWrite);
        _dataView.SafeMemoryMappedViewHandle.AcquirePointer(ref _dataPtr);

        _extView = _mmf.CreateViewAccessor(oldLength, size, MemoryMappedFileAccess.ReadWrite);
        _extView.SafeMemoryMappedViewHandle.AcquirePointer(ref _extPtr);

        return GetExtension();
    }

    public unsafe Span<byte> GetExtension()
    {
        ArgumentNullException.ThrowIfNull(_extView);
        ArgumentNullException.ThrowIfNull(_extPtr);

        int length = (int)_extView.Capacity;
        return new Span<byte>(_extPtr, length);
    }

    public void TruncateDataTo(uint newLength)
    {
        _fileStream.SetLength(newLength);
    }
}