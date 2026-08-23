using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Genbox.FastCodeSign.Abstracts;
using Genbox.FastCodeSign.Allocations;
using Genbox.FastCodeSign.BundleHandlers;
using Genbox.FastCodeSign.Enums;
using Genbox.FastCodeSign.Extensions;
using Genbox.FastCodeSign.Models;

namespace Genbox.FastCodeSign;

public static class CodeSign
{
    public static void SignFile(string filePath, X509Certificate2 cert, bool skipExtCheck = false) => SignFile(filePath, new SignOptions
    {
        Certificate = cert
    }, skipExtCheck);

    public static void SignFile(string filePath, SignOptions signOptions, bool skipExtCheck = false)
        => WaitForCompletion(SignFileAsync(filePath, signOptions, null, skipExtCheck, CancellationToken.None));

    public static void SignFile(string filePath, SignOptions signOptions, IFormatOptions formatOptions, bool skipExtCheck = false)
        => WaitForCompletion(SignFileAsync(filePath, signOptions, formatOptions, skipExtCheck, CancellationToken.None));

    public static void SignFile(string filePath, X509Certificate2 cert, IFormatOptions formatOptions, bool skipExtCheck = false)
        => SignFile(filePath, new SignOptions { Certificate = cert }, formatOptions, skipExtCheck);

    public static async Task SignFileAsync(string filePath, X509Certificate2 cert, bool skipExtCheck = false, CancellationToken cancellationToken = default)
        => await SignFileAsync(filePath, new SignOptions { Certificate = cert }, null, skipExtCheck, cancellationToken).ConfigureAwait(false);

    public static async Task SignFileAsync(string filePath, SignOptions signOptions, bool skipExtCheck = false, CancellationToken cancellationToken = default)
        => await SignFileAsync(filePath, signOptions, null, skipExtCheck, cancellationToken).ConfigureAwait(false);

    /// <summary>
    /// Signs a regular file by replacing it with a completed, same-directory staging file. The destination is unchanged if signing or cancellation fails before replacement.
    /// Symbolic links and reparse points are rejected.
    /// </summary>
    /// <remarks>
    /// This file-path convenience API provides replacement staging. <see cref="CodeSignProvider.SignAsync"/> operates on an arbitrary allocation and does not provide file replacement semantics.
    /// </remarks>
    public static async Task SignFileAsync(string filePath, SignOptions signOptions, IFormatOptions? formatOptions, bool skipExtCheck = false, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(filePath);
        ArgumentNullException.ThrowIfNull(signOptions);
        cancellationToken.ThrowIfCancellationRequested();

        string fullPath = Path.GetFullPath(filePath);
        FileAttributes attributes = File.GetAttributes(fullPath);
        if ((attributes & FileAttributes.ReparsePoint) == FileAttributes.ReparsePoint || new FileInfo(fullPath).LinkTarget != null)
            throw new IOException("Signing symbolic links and reparse points is not supported.");

        DateTime creationTimeUtc = File.GetCreationTimeUtc(fullPath);
        DateTime lastAccessTimeUtc = File.GetLastAccessTimeUtc(fullPath);
        DateTime lastWriteTimeUtc = File.GetLastWriteTimeUtc(fullPath);
        UnixFileMode? unixFileMode = null;
        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
            unixFileMode = File.GetUnixFileMode(fullPath);
        string directory = Path.GetDirectoryName(fullPath)!;
        string temporaryPath = Path.Combine(directory, $".{Path.GetFileNameWithoutExtension(fullPath)}.{Guid.NewGuid():N}.fastcodesign{Path.GetExtension(fullPath)}");

        try
        {
            byte[] sourceHash;
            FileStream source = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, FileOptions.Asynchronous);
            await using (source.ConfigureAwait(false))
            {
                FileStream temporary = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, FileOptions.Asynchronous);
                await using (temporary.ConfigureAwait(false))
                    sourceHash = await CopyAndHashAsync(source, temporary, cancellationToken).ConfigureAwait(false);
            }

            File.SetAttributes(temporaryPath, FileAttributes.Normal);

            using (FileAllocation allocation = new FileAllocation(temporaryPath))
            {
                CodeSignProvider provider = CodeSignProvider.FromAllocation(allocation, null, Path.GetFileName(fullPath), skipExtCheck);
                if (provider.HasSignature())
                {
                    if (signOptions.ExistingSignatureBehavior == ExistingSignatureBehavior.Fail)
                        throw new InvalidOperationException("The file already contains a signature.");
                    provider.TryRemoveSignature(true);
                }

                Signature signature = provider.CreateSignature(signOptions, formatOptions);
                if (signOptions.Timestamp != null)
                    await signature.ApplyTimestampAsync(signOptions.Timestamp, cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                provider.WriteSignature(signature);
            }

            File.SetCreationTimeUtc(temporaryPath, creationTimeUtc);
            File.SetLastAccessTimeUtc(temporaryPath, lastAccessTimeUtc);
            File.SetLastWriteTimeUtc(temporaryPath, lastWriteTimeUtc);
            File.SetAttributes(temporaryPath, attributes);
            if (unixFileMode.HasValue && (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS()))
                File.SetUnixFileMode(temporaryPath, unixFileMode.Value);

            cancellationToken.ThrowIfCancellationRequested();
            FileAttributes currentAttributes = File.GetAttributes(fullPath);
            if ((currentAttributes & FileAttributes.ReparsePoint) != FileAttributes.None || new FileInfo(fullPath).LinkTarget != null)
                throw new IOException("The source file was replaced by a symbolic link or reparse point while it was being signed.");

            byte[] currentHash = await HashFileAsync(fullPath, cancellationToken).ConfigureAwait(false);
            if (!sourceHash.AsSpan().SequenceEqual(currentHash) || File.GetLastWriteTimeUtc(fullPath) != lastWriteTimeUtc || currentAttributes != attributes)
                throw new IOException("The source file changed while it was being signed.");

            File.Replace(temporaryPath, fullPath, null);
        }
        finally
        {
            try
            {
                File.Delete(temporaryPath);
            }
            catch (IOException)
            {
                // Do not mask a signing or replacement failure with cleanup failure.
            }
            catch (UnauthorizedAccessException)
            {
                // Do not mask a signing or replacement failure with cleanup failure.
            }
        }
    }

    public static Span<byte> SignData(byte[] data, X509Certificate2 cert, string? fileName = null, bool skipExtCheck = false) => SignData(data, new SignOptions
    {
        Certificate = cert
    }, fileName, skipExtCheck);

    public static Span<byte> SignData(byte[] data, SignOptions signOptions, string? fileName = null, bool skipExtCheck = false)
        => WaitForCompletion(SignDataAsync(data, signOptions, null, fileName, skipExtCheck, CancellationToken.None)).Span;

    public static Span<byte> SignData(byte[] data, SignOptions signOptions, IFormatOptions formatOptions, string? fileName = null, bool skipExtCheck = false)
        => WaitForCompletion(SignDataAsync(data, signOptions, formatOptions, fileName, skipExtCheck, CancellationToken.None)).Span;

    public static Span<byte> SignData(byte[] data, X509Certificate2 cert, IFormatOptions formatOptions, string? fileName = null, bool skipExtCheck = false)
        => SignData(data, new SignOptions { Certificate = cert }, formatOptions, fileName, skipExtCheck);

    public static async Task<Memory<byte>> SignDataAsync(byte[] data, X509Certificate2 cert, string? fileName = null, bool skipExtCheck = false, CancellationToken cancellationToken = default)
        => await SignDataAsync(data, new SignOptions { Certificate = cert }, null, fileName, skipExtCheck, cancellationToken).ConfigureAwait(false);

    public static async Task<Memory<byte>> SignDataAsync(byte[] data, SignOptions signOptions, string? fileName = null, bool skipExtCheck = false, CancellationToken cancellationToken = default)
        => await SignDataAsync(data, signOptions, null, fileName, skipExtCheck, cancellationToken).ConfigureAwait(false);

    public static async Task<Memory<byte>> SignDataAsync(byte[] data, SignOptions signOptions, IFormatOptions? formatOptions, string? fileName = null, bool skipExtCheck = false, CancellationToken cancellationToken = default)
    {
        CodeSignProvider provider = CodeSignProvider.FromData(data, null, fileName, skipExtCheck);
        await provider.SignAsync(signOptions, formatOptions, cancellationToken).ConfigureAwait(false);
        return provider.Allocation.GetSpan().ToArray();
    }

    public static void SignBundle(string path, X509Certificate2 cert) => SignBundle(path, new SignOptions
    {
        Certificate = cert,
    });

    public static void SignBundle(string path, SignOptions signOptions)
        => WaitForCompletion(SignBundleAsync(path, signOptions, null, CancellationToken.None));

    public static void SignBundle(string path, SignOptions signOptions, IBundleOptions bundleOptions)
        => WaitForCompletion(SignBundleAsync(path, signOptions, bundleOptions, CancellationToken.None));

    public static void SignBundle(string path, SignOptions signOptions, AppBundleOptions bundleOptions)
        => WaitForCompletion(SignBundleAsync(path, signOptions, bundleOptions, CancellationToken.None));

    public static async Task SignBundleAsync(string path, X509Certificate2 cert, CancellationToken cancellationToken = default)
        => await SignBundleAsync(path, new SignOptions { Certificate = cert }, null, cancellationToken).ConfigureAwait(false);

    public static async Task SignBundleAsync(string path, SignOptions signOptions, CancellationToken cancellationToken = default)
        => await SignBundleAsync(path, signOptions, null, cancellationToken).ConfigureAwait(false);

    public static async Task SignBundleAsync(string path, SignOptions signOptions, IBundleOptions? bundleOptions, CancellationToken cancellationToken = default)
    {
        CodeSignBundleProvider provider = CodeSignProvider.FromBundle(path);
        await provider.SignAsync(signOptions, bundleOptions, cancellationToken).ConfigureAwait(false);
    }

    [SuppressMessage("Usage", "VSTHRD002:Avoid problematic synchronous waits", Justification = "Public synchronous compatibility wrappers intentionally bridge asynchronous timestamp support.")]
    private static void WaitForCompletion(Task task) => task.GetAwaiter().GetResult();

    [SuppressMessage("Usage", "VSTHRD002:Avoid problematic synchronous waits", Justification = "Public synchronous compatibility wrappers intentionally bridge asynchronous timestamp support.")]
    private static T WaitForCompletion<T>(Task<T> task) => task.GetAwaiter().GetResult();

    private static async Task<byte[]> CopyAndHashAsync(Stream source, Stream destination, CancellationToken cancellationToken)
    {
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] buffer = ArrayPool<byte>.Shared.Rent(81920);
        try
        {
            while (true)
            {
                int read = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                    return hash.GetHashAndReset();

                hash.AppendData(buffer.AsSpan(0, read));
                await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static async Task<byte[]> HashFileAsync(string path, CancellationToken cancellationToken)
    {
        FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, FileOptions.Asynchronous);
        await using (stream.ConfigureAwait(false))
            return await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
    }
}