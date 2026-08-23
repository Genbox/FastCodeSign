using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Genbox.FastCodeSign.Abstracts;
using Genbox.FastCodeSign.BundleHandlers;
using Genbox.FastCodeSign.Enums;
using Genbox.FastCodeSign.Extensions;
using Genbox.FastCodeSign.Internal.Helpers;
using Genbox.FastCodeSign.Models;

namespace Genbox.FastCodeSign;

public class CodeSignBundleProvider
{
    private readonly IBundleHandler _handler;
    private readonly string _path;

    internal CodeSignBundleProvider(IBundleHandler handler, string path)
    {
        _handler = handler;
        _path = path;
    }

    /// <summary>Creates a bundle signature and may re-sign nested code immediately.</summary>
    public BundleSignature CreateSignature(SignOptions options)
        => CreateSignature(options, (IBundleOptions?)null);

    public BundleSignature CreateSignature(SignOptions options, IBundleOptions? bundleOptions)
    {
        IContext context = _handler.GetContext(_path);

        if (context.IsSigned)
            throw new InvalidOperationException("The bundle is already signed.");

        return _handler.CreateSignature(context, options, bundleOptions);
    }

    public BundleSignature CreateSignature(SignOptions options, AppBundleOptions bundleOptions)
        => CreateSignature(options, (IBundleOptions)bundleOptions);

    /// <summary>Writes a signature immediately. This low-level operation mutates the bundle.</summary>
    public void WriteSignature(BundleSignature signature)
    {
        IContext context = _handler.GetContext(_path);

        if (context.IsSigned)
            throw new InvalidOperationException("The bundle already contains a signature.");

        _handler.WriteSignature(context, signature);
    }

    /// <summary>Removes the current signature immediately. This low-level operation mutates the bundle.</summary>
    public SignatureComponent RemoveSignature()
    {
        IContext context = _handler.GetContext(_path);

        if (!context.IsSigned)
            return SignatureComponent.None;

        return _handler.RemoveSignature(context);
    }

    public bool HasValidSignature()
    {
        IContext context = _handler.GetContext(_path);

        if (!context.IsSigned)
            return false;

        return _handler.HasValidSignature(context);
    }

    /// <summary>
    /// Creates, optionally timestamps, and writes a bundle signature in a sibling staging directory. The original bundle is not changed before signing and timestamping succeed.
    /// </summary>
    public async Task SignAsync(SignOptions options, IBundleOptions? bundleOptions = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        cancellationToken.ThrowIfCancellationRequested();

        string fullPath = Path.GetFullPath(_path);
        if (PathHelper.IsReparsePoint(fullPath))
            throw new IOException("Signing a bundle through a symbolic link or reparse point is not supported.");

        string parent = Path.GetDirectoryName(fullPath)!;
        string stagingPath = Path.Combine(parent, $".{Path.GetFileName(fullPath)}.{Guid.NewGuid():N}.fcs-staging");
        string backupPath = Path.Combine(parent, $".{Path.GetFileName(fullPath)}.{Guid.NewGuid():N}.fcs-backup");
        bool installed = false;
        bool backupCreated = false;
        try
        {
            byte[] originalState = CaptureDirectoryState(fullPath, cancellationToken);
            CopyDirectory(fullPath, stagingPath, cancellationToken);
            if (!originalState.AsSpan().SequenceEqual(CaptureDirectoryState(stagingPath, cancellationToken)))
                throw new IOException("The bundle changed while it was being copied.");

            CodeSignBundleProvider stagedProvider = new CodeSignBundleProvider(_handler, stagingPath);
            if (stagedProvider._handler.GetContext(stagingPath).IsSigned)
            {
                if (options.ExistingSignatureBehavior == ExistingSignatureBehavior.Fail)
                    throw new InvalidOperationException("The bundle is already signed.");
                stagedProvider.RemoveSignature();
            }

            BundleSignature signature = stagedProvider.CreateSignature(options, bundleOptions);
            if (options.Timestamp != null)
                await signature.ApplyTimestampAsync(options.Timestamp, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            stagedProvider.WriteSignature(signature);

            if (PathHelper.IsReparsePoint(fullPath) || !originalState.AsSpan().SequenceEqual(CaptureDirectoryState(fullPath, cancellationToken)))
                throw new IOException("The bundle changed while it was being signed.");

            Directory.Move(fullPath, backupPath);
            backupCreated = true;
            try
            {
                Directory.Move(stagingPath, fullPath);
                installed = true;
            }
            catch (Exception ex)
            {
                if (!PathExists(fullPath) && Directory.Exists(backupPath))
                {
                    Directory.Move(backupPath, fullPath);
                    throw;
                }

                if (PathExists(fullPath) && Directory.Exists(backupPath))
                {
                    string conflictPath = Path.Combine(parent, $".{Path.GetFileName(fullPath)}.{Guid.NewGuid():N}.fcs-conflict");
                    MovePath(fullPath, conflictPath);
                    Directory.Move(backupPath, fullPath);
                    throw new IOException($"Another filesystem entry appeared while the signed bundle was being installed. The original bundle was restored and the conflicting entry was preserved at '{conflictPath}'.", ex);
                }

                throw;
            }

            // The replacement is installed at this point. A stale backup is safer than undoing it.
            TryDeleteDirectory(backupPath);
        }
        finally
        {
            if (!installed && backupCreated && !PathExists(fullPath) && Directory.Exists(backupPath))
                Directory.Move(backupPath, fullPath);

            TryDeleteDirectory(stagingPath);

            if (installed)
                TryDeleteDirectory(backupPath);
        }
    }

    public Task SignAsync(SignOptions options, AppBundleOptions bundleOptions, CancellationToken cancellationToken = default)
        => SignAsync(options, (IBundleOptions)bundleOptions, cancellationToken);

    private static void CopyDirectory(string source, string destination, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(destination);
        foreach (string entry in Directory.EnumerateFileSystemEntries(source))
        {
            cancellationToken.ThrowIfCancellationRequested();

            string target = Path.Combine(destination, Path.GetFileName(entry));
            FileAttributes attributes = File.GetAttributes(entry);
            bool isDirectory = (attributes & FileAttributes.Directory) == FileAttributes.Directory;
            bool isLink = (attributes & FileAttributes.ReparsePoint) == FileAttributes.ReparsePoint;

            if (isLink)
            {
                FileSystemInfo info = isDirectory ? new DirectoryInfo(entry) : new FileInfo(entry);
                string linkTarget = info.LinkTarget ?? throw new IOException($"Unable to read symlink target '{entry}'.");
                if (isDirectory)
                    Directory.CreateSymbolicLink(target, linkTarget);
                else
                    File.CreateSymbolicLink(target, linkTarget);
                continue;
            }

            if (isDirectory)
            {
                CopyDirectory(entry, target, cancellationToken);
                CopyMetadata(entry, target);
            }
            else
            {
                File.Copy(entry, target);
                CopyMetadata(entry, target);
            }
        }

        CopyMetadata(source, destination);
    }

    private static void CopyMetadata(string source, string destination)
    {
        try
        {
            if (Directory.Exists(destination))
            {
                Directory.SetCreationTimeUtc(destination, Directory.GetCreationTimeUtc(source));
                Directory.SetLastWriteTimeUtc(destination, Directory.GetLastWriteTimeUtc(source));
                Directory.SetLastAccessTimeUtc(destination, Directory.GetLastAccessTimeUtc(source));
            }
            else
            {
                File.SetCreationTimeUtc(destination, File.GetCreationTimeUtc(source));
                File.SetLastWriteTimeUtc(destination, File.GetLastWriteTimeUtc(source));
                File.SetLastAccessTimeUtc(destination, File.GetLastAccessTimeUtc(source));
            }
            if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
                File.SetUnixFileMode(destination, File.GetUnixFileMode(source));
        }
        catch (PlatformNotSupportedException)
        {
            // Unix modes are not available on every target filesystem.
        }

        FileAttributes attributes = File.GetAttributes(source) & (FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.System | FileAttributes.Archive | FileAttributes.Temporary | FileAttributes.Offline | FileAttributes.NotContentIndexed);
        File.SetAttributes(destination, attributes);
    }

    private static byte[] CaptureDirectoryState(string root, CancellationToken cancellationToken)
    {
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        AppendDirectoryState(hash, root, root, cancellationToken);
        return hash.GetHashAndReset();
    }

    private static void AppendDirectoryState(IncrementalHash hash, string root, string directory, CancellationToken cancellationToken)
    {
        Span<byte> length = stackalloc byte[sizeof(long)];
        foreach (string entry in Directory.EnumerateFileSystemEntries(directory).Order(StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            string relative = Path.GetRelativePath(root, entry).Replace(Path.DirectorySeparatorChar, '/');
            FileAttributes attributes = File.GetAttributes(entry);
            bool isDirectory = (attributes & FileAttributes.Directory) != FileAttributes.None;
            bool isLink = (attributes & FileAttributes.ReparsePoint) != FileAttributes.None;
            string entryType = isLink ? "L" : "F";
            if (isDirectory && !isLink)
                entryType = "D";
            AppendString(hash, entryType);
            AppendString(hash, relative);

            if (isLink)
            {
                FileSystemInfo info = isDirectory ? new DirectoryInfo(entry) : new FileInfo(entry);
                AppendString(hash, info.LinkTarget ?? throw new IOException($"Unable to read symlink target '{entry}'."));
                continue;
            }

            if (isDirectory)
            {
                AppendDirectoryState(hash, root, entry, cancellationToken);
                continue;
            }

            using FileStream stream = new FileStream(entry, FileMode.Open, FileAccess.Read, FileShare.Read);
            BinaryPrimitives.WriteInt64LittleEndian(length, stream.Length);
            hash.AppendData(length);

            byte[] buffer = ArrayPool<byte>.Shared.Rent(81920);
            try
            {
                while (true)
                {
                    int read = stream.Read(buffer);
                    if (read == 0)
                        break;
                    hash.AppendData(buffer.AsSpan(0, read));
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }
    }

    private static void AppendString(IncrementalHash hash, string value)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value);
        Span<byte> length = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(length, bytes.Length);
        hash.AppendData(length);
        hash.AppendData(bytes);
    }

    private static bool PathExists(string path)
    {
        try
        {
            File.GetAttributes(path);
            return true;
        }
        catch (FileNotFoundException)
        {
            return false;
        }
        catch (DirectoryNotFoundException)
        {
            return false;
        }
    }

    private static void MovePath(string source, string destination)
    {
        FileAttributes attributes = File.GetAttributes(source);
        if ((attributes & FileAttributes.Directory) != FileAttributes.None)
            Directory.Move(source, destination);
        else
            File.Move(source, destination);
    }

    private static void TryDeleteDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path))
                Directory.Delete(path, true);
        }
        catch (IOException)
        {
            // Do not turn a successful atomic replacement into a failed signing operation.
        }
        catch (UnauthorizedAccessException)
        {
            // The stale sibling directory can be cleaned up later if the filesystem rejects deletion.
        }
    }
}