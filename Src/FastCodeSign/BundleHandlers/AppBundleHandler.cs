using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using Genbox.FastCodeSign.Abstracts;
using Genbox.FastCodeSign.Allocations;
using Genbox.FastCodeSign.Enums;
using Genbox.FastCodeSign.Extensions;
using Genbox.FastCodeSign.Handlers;
using Genbox.FastCodeSign.Helpers;
using Genbox.FastCodeSign.Internal.Bundles;
using Genbox.FastCodeSign.Internal.MachObject;
using Genbox.FastCodeSign.Internal.MachObject.Headers.Enums;
using Genbox.FastCodeSign.MachObjects;
using Genbox.FastCodeSign.Models;

namespace Genbox.FastCodeSign.BundleHandlers;

public sealed class AppBundleHandler : IBundleHandler
{
    public IContext GetContext(string path) => AppBundleContext.Create(path);

    public bool IsBundlePath(string path) => File.Exists(Path.Combine(path, "Contents", "Info.plist"));

    public BundleSignature CreateSignature(IContext context, SignOptions signOptions, IBundleOptions? bundleOptions = null)
    {
        AppBundleContext obj = (AppBundleContext)context;
        AppBundleOptions opt = bundleOptions == null ? new AppBundleOptions() : (AppBundleOptions)bundleOptions;

        Requirements? req = opt.Requirements;

        if (req == null)
            if (signOptions.Certificate.IsAppleDeveloperCertificate())
                req = Requirements.CreateAppleDevDefault(obj.Identifier, signOptions.Certificate);
            else
                req = Requirements.CreateDefault(obj.Identifier, signOptions.Certificate);

        byte[] requirementsBytes = req.ToArray();

        Entitlements? entitlements = opt.Entitlements;

        ExecSegFlags segmentFlags = ExecSegFlags.MainBinary;
        byte[]? entitlementsXmlBytes = null;
        byte[]? entitlementsDerBytes = null;

        if (entitlements != null)
        {
            segmentFlags |= MachObjectFormatHandler.GetExecSegFlags(entitlements);
            entitlementsXmlBytes = entitlements.EncodeAsXml();
            entitlementsDerBytes = entitlements.EncodeAsDer();
        }

        Dictionary<string, object>? resourceSeal = opt.ResourcesPropertyList;
        byte[]? resourcesBytes = null;

        using MemoryStream ms = new MemoryStream();

        if (resourceSeal != null)
        {
            ms.SetLength(0);
            PListSerializer.Serialize(resourceSeal, ms);
            resourcesBytes = ms.ToArray();
        }

        Dictionary<string, object>? propertyList = opt.InfoPropertyList;
        byte[]? infoBytes = null;

        if (propertyList != null)
        {
            ms.SetLength(0);
            PListSerializer.Serialize(propertyList, ms);
            infoBytes = ms.ToArray();
        }

        Dictionary<string, object> pList = BuildPList(obj); // Do not inline

        IFormatHandler handler = new MachObjectFormatHandler();
        using FileAllocation file = new FileAllocation(obj.BundleExecutablePath);
        ReadOnlySpan<byte> dataSpan = file.GetSpan();

        MachObject[] objs = MachObjectHelper.GetMachObjects(dataSpan);
        Signature[] signatures = new Signature[objs.Length];

        for (int i = 0; i < objs.Length; i++)
        {
            ReadOnlySpan<byte> objSpan = objs[i].GetSpan(dataSpan);
            MachOContext machOContext = (MachOContext)handler.GetContext(objSpan);
            signatures[i] = MachObjectFormatHandler.CreateSignature(machOContext, objSpan, signOptions, obj.Identifier, opt.TeamId, segmentFlags, requirementsBytes, entitlementsXmlBytes, entitlementsDerBytes, resourcesBytes, infoBytes, null);
        }

        // Sign the resources
        return new BundleSignature(signatures, new AppBundleInfo { CodeResources = pList });
    }

    void IBundleHandler.WriteSignature(IContext context, BundleSignature signature)
    {
        AppBundleContext obj = (AppBundleContext)context;
        AppBundleInfo info = (AppBundleInfo)signature.BundleInfo!;

        // Write the Content/_CodeSignature/CodeResources file if we have it
        string codeSigPath = Path.Combine(obj.BundlePath, "Contents", "_CodeSignature");

        if (!Directory.Exists(codeSigPath))
            Directory.CreateDirectory(codeSigPath);

        string codeResFile = Path.Combine(codeSigPath, "CodeResources");
        using FileStream fs = File.Create(codeResFile);
        PListSerializer.Serialize(info.CodeResources, fs);

        // Write the signature(s) to the mach object file
        using FileAllocation file = new FileAllocation(obj.BundleExecutablePath);
        Span<byte> span = file.GetSpan();

        MachObject[] machObjects = MachObjectHelper.GetMachObjects(span);
        Debug.Assert(signature.Signatures.Length == machObjects.Length, "The number of signatures does not match the number of mach object slices.");

        MachMagic magic = (MachMagic)ReadUInt32BigEndian(span);

        switch (magic)
        {
            case MachMagic.FatMagicBE or MachMagic.FatMagicLE:
                WriteFatSignature(file, machObjects, signature.Signatures, false);
                break;
            case MachMagic.FatMagic64BE or MachMagic.FatMagic64LE:
                WriteFatSignature(file, machObjects, signature.Signatures, true);
                break;
            default:
                WriteThinSignature(span, file, signature.Signatures[0]);
                break;
        }
    }

    public SignatureComponent RemoveSignature(IContext context)
    {
        AppBundleContext obj = (AppBundleContext)context;
        SignatureComponent removed = SignatureComponent.None;

        string contentsPath = Path.Combine(obj.BundlePath, "Contents");

        string legacyCodeSignaturePath = Path.Combine(contentsPath, "CodeResources");

        if (File.Exists(legacyCodeSignaturePath))
        {
            File.Delete(legacyCodeSignaturePath);
            removed |= SignatureComponent.LegacyCodeResourcesFile;
        }

        // Remove the resource seal (if there is one)
        string codeSignaturePath = Path.Combine(contentsPath, "_CodeSignature");

        if (Directory.Exists(codeSignaturePath))
        {
            string codeResourcesPath = Path.Combine(codeSignaturePath, "CodeResources");

            if (File.Exists(codeResourcesPath))
            {
                File.Delete(codeResourcesPath);
                removed |= SignatureComponent.CodeResourcesFile;
            }

            // If there are no more files in the directory. Delete it.
            if (Directory.GetFileSystemEntries(codeSignaturePath).Length == 0)
            {
                Directory.Delete(codeSignaturePath);
                removed |= SignatureComponent.CodeSignatureFolder;
            }
        }

        using FileAllocation allocation = new FileAllocation(obj.BundleExecutablePath);
        IFormatHandler handler = new MachObjectFormatHandler();

        Span<byte> span = allocation.GetSpan();

        MachObject[] objs = MachObjectHelper.GetMachObjects(span);

        foreach (MachObject machObject in objs)
        {
            Span<byte> objSpan = machObject.GetSpan(span);
            IContext machContext = handler.GetContext(objSpan);

            if (machContext.IsSigned)
            {
                handler.RemoveSignature(machContext, objSpan);
                removed |= SignatureComponent.MachObjectSignature;
            }
        }

        return removed;
    }

    public bool HasValidSignature(IContext context)
    {
        AppBundleContext obj = (AppBundleContext)context;

        if (!obj.IsSigned)
            return false;

        // Check if the signature in the mach object is valid
        IFormatHandler handler = new MachObjectFormatHandler();
        using (FileAllocation allocation = new FileAllocation(obj.BundleExecutablePath))
        {
            Span<byte> span = allocation.GetSpan();

            MachObject[] objs = MachObjectHelper.GetMachObjects(span);

            foreach (MachObject machObject in objs)
            {
                ReadOnlySpan<byte> objSpan = machObject.GetSpan(span);
                IContext objContext = handler.GetContext(objSpan);

                ReadOnlySpan<byte> signatureBytes = handler.ExtractSignature(objContext, objSpan);
                Debug.Assert(!signatureBytes.IsEmpty);

                // Extra sanity checks before delegating decoding to SignedCms
                if (AsnDecoder.TryReadEncodedValue(signatureBytes, AsnEncodingRules.BER, out Asn1Tag tag, out _, out _, out int bytesConsumed))
                {
                    if (!tag.HasSameClassAndValue(Asn1Tag.Sequence))
                        throw new InvalidOperationException("The ASN.1 structure is invalid");

                    if (signatureBytes.Length != bytesConsumed)
                        throw new InvalidDataException("There is trailing data after the ASN.1 structure");
                }

                SignedCms signedCms = new SignedCms();
                signedCms.Decode(signatureBytes);

                if (!handler.ExtractHashFromSignedCms(signedCms, out byte[]? expectedDigest, out HashAlgorithmName hashAlgorithm))
                    throw new InvalidOperationException("The CMS does not contain a valid hash.");

                byte[] actualDigest = handler.ComputeHash(objContext, objSpan, hashAlgorithm);
                if (!expectedDigest.SequenceEqual(actualDigest))
                    return false;
            }
        }

        return VerifyResourceSeal(obj);
    }

    private static bool VerifyResourceSeal(AppBundleContext context)
    {
        // Deserialize the property list
        Dictionary<string, object> pList = PListSerializer.Deserialize(File.ReadAllBytes(Path.Combine(context.BundlePath, "Contents", "_CodeSignature", "CodeResources")));
        Dictionary<string, object> files2 = (Dictionary<string, object>)pList["files2"];

        string contents = Path.Combine(context.BundlePath, "Contents");

        foreach ((string relativePath, object value) in files2)
        {
            if (!ValidateFiles2Entry(contents, relativePath, value))
                return false;
        }

        return true;
    }

    private static bool ValidateFiles2Entry(string contentsRoot, string relativePath, object value)
    {
        string fullPath = Path.Combine(contentsRoot, relativePath);

        if (value is byte[] hashBytes)
            return ValidateFileHash(fullPath, hashBytes, HashAlgorithmName.SHA256);

        if (value is not Dictionary<string, object> dict)
            throw new InvalidDataException($"Unsupported CodeResources entry type for '{relativePath}'.");

        if (dict.TryGetValue("cdhash", out object? cdHashObj) && cdHashObj is byte[] cdHash)
        {
            if (!Directory.Exists(fullPath))
                return false;

            if (!ValidateCdHash(fullPath, cdHash))
                return false;

            return ValidateMachSignature(fullPath);
        }

        if (dict.TryGetValue("symlink", out object? symlinkObj) && symlinkObj is string expectedTarget)
        {
            if (!File.Exists(fullPath) && !Directory.Exists(fullPath))
                return false;

            FileAttributes attrs = File.GetAttributes(fullPath);
            if ((attrs & FileAttributes.ReparsePoint) == FileAttributes.None)
                return false;

            FileSystemInfo fsi = (attrs & FileAttributes.Directory) != FileAttributes.None ? new DirectoryInfo(fullPath) : new FileInfo(fullPath);
            return string.Equals(fsi.LinkTarget, expectedTarget, StringComparison.Ordinal);
        }

        if (dict.TryGetValue("hash2", out object? hash2Obj) && hash2Obj is byte[] hash2)
            return ValidateFileHash(fullPath, hash2, HashAlgorithmName.SHA256);

        return false;
    }

    private static bool ValidateFileHash(string fullPath, byte[] expectedHash, HashAlgorithmName algo)
    {
        if (!File.Exists(fullPath))
            return false;

        using FileStream fs = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        byte[] actual = algo == HashAlgorithmName.SHA256 ? SHA256.HashData(fs) : SHA1.HashData(fs);
        return expectedHash.SequenceEqual(actual);
    }

    private static bool ValidateCdHash(string bundlePath, byte[] expectedCdHash)
    {
        if (!TryResolveExecutablePath(bundlePath, out string? executablePath))
            return false;

        IFormatHandler formatHandler = new MachObjectFormatHandler();

        using FileAllocation allocation = new FileAllocation(executablePath);
        Span<byte> span = allocation.GetSpan();

        MachObject[] objs = MachObjectHelper.GetMachObjects(span);

        if (objs.Length == 0)
            return TryMatchCdHash(formatHandler, span, expectedCdHash);

        foreach (MachObject machObject in objs)
        {
            ReadOnlySpan<byte> objSpan = machObject.GetSpan(span);
            if (TryMatchCdHash(formatHandler, objSpan, expectedCdHash))
                return true;
        }

        return false;
    }

    private static bool TryMatchCdHash(IFormatHandler handler, ReadOnlySpan<byte> objSpan, byte[] expectedCdHash)
    {
        IContext machContext = handler.GetContext(objSpan);

        ReadOnlySpan<byte> signatureBytes = handler.ExtractSignature(machContext, objSpan);
        SignedCms signedCms = new SignedCms();
        signedCms.Decode(signatureBytes);

        if (!handler.ExtractHashFromSignedCms(signedCms, out byte[]? digest, out _))
            return false;

        ReadOnlySpan<byte> cdHash = digest.Length > 20 ? digest.AsSpan(0, 20) : digest;

        return cdHash.SequenceEqual(expectedCdHash);
    }

    private static bool ValidateMachSignature(string bundlePath)
    {
        if (!TryResolveExecutablePath(bundlePath, out string? executablePath))
            return false;

        IFormatHandler handler = new MachObjectFormatHandler();

        using FileAllocation allocation = new FileAllocation(executablePath);
        Span<byte> span = allocation.GetSpan();

        MachObject[] objs = MachObjectHelper.GetMachObjects(span);

        if (objs.Length == 0)
            return ValidateSlice(handler, span);

        foreach (MachObject machObject in objs)
        {
            ReadOnlySpan<byte> objSpan = machObject.GetSpan(span);
            if (!ValidateSlice(handler, objSpan))
                return false;
        }

        return true;

        static bool ValidateSlice(IFormatHandler handler, ReadOnlySpan<byte> objSpan)
        {
            IContext machContext = handler.GetContext(objSpan);

            if (!machContext.IsSigned)
                return false;

            ReadOnlySpan<byte> signatureBytes = handler.ExtractSignature(machContext, objSpan);
            SignedCms signedCms = new SignedCms();
            signedCms.Decode(signatureBytes);

            if (!handler.ExtractHashFromSignedCms(signedCms, out byte[]? expectedDigest, out HashAlgorithmName algo))
                return false;

            byte[] actualDigest = handler.ComputeHash(machContext, objSpan, algo);
            return expectedDigest.SequenceEqual(actualDigest);
        }
    }

    private static bool TryResolveExecutablePath(string bundlePath, [NotNullWhen(true)]out string? executablePath)
    {
        executablePath = null;

        string? infoPath = FindInfoPlist(bundlePath, out string? execName);
        execName ??= Path.GetFileNameWithoutExtension(bundlePath);

        HashSet<string> candidates =
        [
            Path.Combine(bundlePath, "Contents", "MacOS", execName),
            Path.Combine(bundlePath, execName),
            Path.Combine(bundlePath, "Versions", "Current", execName),
            Path.Combine(bundlePath, "Versions", "A", execName)
        ];

        if (infoPath != null)
        {
            string infoDir = Path.GetDirectoryName(infoPath)!;
            string? parent = Directory.GetParent(infoDir)?.FullName;

            if (parent != null)
                candidates.Add(Path.Combine(parent, execName));
        }

        foreach (string candidate in candidates)
        {
            FileInfo fi = new FileInfo(candidate);

            if (!fi.Exists || fi.Length == 0)
                continue;

            executablePath = candidate;
            return true;
        }

        return false;
    }

    private static void WriteThinSignature(Span<byte> span, FileAllocation file, Signature machSignature)
    {
        IFormatHandler handler = new MachObjectFormatHandler();
        IContext machContext = handler.GetContext(span);
        handler.WriteSignature(machContext, file, machSignature);
    }

    private static void WriteFatSignature(FileAllocation unsignedFile, MachObject[] machObjects, Signature[] signatures, bool isFat64)
    {
        MachMagic magic = isFat64 ? MachMagic.FatMagic64BE : MachMagic.FatMagicBE;
        IFormatHandler handler = new MachObjectFormatHandler();

        ReadOnlySpan<byte> unsignedSpan = unsignedFile.GetSpan();

        string tempPath = unsignedFile.FilePath + ".tmp";
        int archHeaderSize = isFat64 ? 32 : 20;
        int headerSize = 8 + (machObjects.Length * archHeaderSize);
        byte[] headerBuffer = new byte[headerSize];

        try
        {
            using FileStream tempStream = new FileStream(tempPath, FileMode.Create, FileAccess.ReadWrite, FileShare.None);
            Span<byte> headerSpan = headerBuffer;

            WriteUInt32BigEndian(headerSpan, (uint)magic);
            WriteUInt32BigEndian(headerSpan[4..], (uint)machObjects.Length);

            // Reserve header space
            tempStream.SetLength(headerSize);

            ulong offset = (ulong)headerSize;

            for (int i = 0; i < machObjects.Length; i++)
            {
                ReadOnlySpan<byte> objSpan = machObjects[i].GetSpan(unsignedSpan);

                MemoryAllocation allocation = new MemoryAllocation(objSpan.ToArray());
                IContext machContext = handler.GetContext(allocation.GetSpan());
                handler.WriteSignature(machContext, allocation, signatures[i]);

                Span<byte> signedSpan = allocation.GetSpan();

                offset = Align(offset, 1UL << (int)machObjects[i].Align);
                tempStream.Position = (long)offset;
                tempStream.Write(signedSpan);

                int archOffset = 8 + (i * archHeaderSize);

                WriteUInt32BigEndian(headerSpan[archOffset..], (uint)machObjects[i].CpuType);
                WriteUInt32BigEndian(headerSpan[(archOffset + 4)..], Convert.ToUInt32(machObjects[i].CpuSubType));

                if (isFat64)
                {
                    WriteUInt64BigEndian(headerSpan[(archOffset + 8)..], offset);
                    WriteUInt64BigEndian(headerSpan[(archOffset + 16)..], (ulong)signedSpan.Length);
                    WriteUInt32BigEndian(headerSpan[(archOffset + 24)..], machObjects[i].Align);
                    WriteUInt32BigEndian(headerSpan[(archOffset + 28)..], 0);
                }
                else
                {
                    WriteUInt32BigEndian(headerSpan[(archOffset + 8)..], checked((uint)offset));
                    WriteUInt32BigEndian(headerSpan[(archOffset + 12)..], checked((uint)signedSpan.Length));
                    WriteUInt32BigEndian(headerSpan[(archOffset + 16)..], machObjects[i].Align);
                }

                offset += (ulong)signedSpan.Length;
            }

            tempStream.SetLength((long)offset);
            tempStream.Position = 0;
            tempStream.Write(headerBuffer);
            tempStream.Flush();
            tempStream.Position = 0;

            unsignedFile.SetLength(checked((uint)offset));
            Span<byte> dest = unsignedFile.GetSpan();
            int copied = 0;

            while (true)
            {
                int read = tempStream.Read(dest[copied..]);

                if (read == 0)
                    break;

                copied += read;
            }
        }
        finally
        {
            if (File.Exists(tempPath))
                File.Delete(tempPath);
        }
    }

    private static string? FindInfoPlist(string bundlePath, out string? execName)
    {
        string[] possible =
        [
            Path.Combine(bundlePath, "Contents", "Info.plist"),
            Path.Combine(bundlePath, "Resources", "Info.plist"),
            Path.Combine(bundlePath, "Info.plist"),
            Path.Combine(bundlePath, "Versions", "Current", "Resources", "Info.plist"),
            Path.Combine(bundlePath, "Versions", "A", "Resources", "Info.plist")
        ];

        foreach (string path in possible)
        {
            if (!File.Exists(path))
                continue;

            Dictionary<string, object> plist = PListSerializer.Deserialize(File.ReadAllBytes(path));

            execName = plist.TryGetValue("CFBundleExecutable", out object? execObj) ? (string)execObj : null;
            return path;
        }

        execName = null;
        return null;
    }

    private static Dictionary<string, object> BuildPList(AppBundleContext obj)
    {
        Dictionary<string, object> files2 = new Dictionary<string, object>(StringComparer.Ordinal);

        string contentsPath = Path.Combine(obj.BundlePath, "Contents");
        foreach (string entry in Directory.EnumerateFileSystemEntries(contentsPath, "*", SearchOption.AllDirectories))
        {
            string relative = Path.GetRelativePath(contentsPath, entry);
            relative = relative.Replace(Path.DirectorySeparatorChar, '/');

            // Skip our own signature artifacts
            if (relative.StartsWith("_CodeSignature", StringComparison.Ordinal) || string.Equals(relative, "CodeResources", StringComparison.Ordinal))
                continue;

            FileAttributes attrs = File.GetAttributes(entry);
            bool isDir = (attrs & FileAttributes.Directory) != FileAttributes.None;
            bool isReparse = (attrs & FileAttributes.ReparsePoint) != FileAttributes.None;

            if (isDir && !isReparse)
                continue; // Directories are represented by their contents

            Dictionary<string, object> files2Value = new Dictionary<string, object>(3);

            if (isReparse)
            {
                FileSystemInfo fsi = isDir ? new DirectoryInfo(entry) : new FileInfo(entry);
                if (fsi.LinkTarget != null)
                    files2Value.Add("symlink", fsi.LinkTarget);
                else
                    throw new InvalidDataException($"Unable to resolve symlink target for '{relative}'.");
            }
            else
            {
                using FileStream fs = File.OpenRead(entry);
                files2Value.Add("hash2", SHA256.HashData(fs));
            }

            files2.Add(relative, files2Value);
        }

        return new Dictionary<string, object>
        {
            { "files2", files2 }
        };
    }

    private sealed class AppBundleInfo
    {
        internal required Dictionary<string, object> CodeResources { get; init; }
    }
}