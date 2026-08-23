using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using Genbox.FastCodeSign.Abstracts;
using Genbox.FastCodeSign.Allocations;
using Genbox.FastCodeSign.Enums;
using Genbox.FastCodeSign.Extensions;
using Genbox.FastCodeSign.Handlers;
using Genbox.FastCodeSign.Helpers;
using Genbox.FastCodeSign.Internal.Bundles;
using Genbox.FastCodeSign.Internal.Helpers;
using Genbox.FastCodeSign.Internal.MachObject;
using Genbox.FastCodeSign.Internal.MachObject.Headers.Enums;
using Genbox.FastCodeSign.MachObjects;
using Genbox.FastCodeSign.Models;

namespace Genbox.FastCodeSign.BundleHandlers;

public sealed class AppBundleHandler : IBundleHandler
{
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromSeconds(1);

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

        Dictionary<string, object> signingRules2 = opt.ResourcesPropertyList?.TryGetValue("rules2", out object? customRules) == true && customRules is Dictionary<string, object> customRules2 ? customRules2 : BuildRules2();
        // FCS-002: Nested code is signed before the parent envelope captures its CodeDirectory hash.
        string? teamId = opt.TeamId ?? (signOptions.Certificate.IsAppleDeveloperCertificate() ? signOptions.Certificate.GetTeamId() : null);
        CdFlags codeDirectoryFlags = MachObjectFormatHandler.GetCodeDirectoryFlags(opt.SigningFlags);
        SignNestedCode(obj, signOptions, signingRules2, teamId, opt.SigningFlags);

        Dictionary<string, object> pList = opt.ResourcesPropertyList ?? BuildPList(obj, signOptions.Certificate);
        byte[] resourcesBytes = SerializePList(pList);

        Dictionary<string, object>? propertyList = opt.InfoPropertyList;
        byte[] infoBytes = File.ReadAllBytes(Path.Combine(obj.BundlePath, "Contents", "Info.plist"));
        if (propertyList != null && !SerializePList(propertyList).AsSpan().SequenceEqual(infoBytes))
            throw new InvalidOperationException("InfoPropertyList must serialize to the exact on-disk Info.plist bytes.");

        IFormatHandler handler = new MachObjectFormatHandler();
        using FileAllocation file = new FileAllocation(obj.BundleExecutablePath);
        ReadOnlySpan<byte> dataSpan = file.GetSpan();

        MachObject[] objs = MachObjectHelper.GetMachObjects(dataSpan);
        Signature[] signatures = new Signature[objs.Length];

        for (int i = 0; i < objs.Length; i++)
        {
            ReadOnlySpan<byte> objSpan = objs[i].GetSpan(dataSpan);
            MachOContext machOContext = (MachOContext)handler.GetContext(objSpan);
            signatures[i] = MachObjectFormatHandler.CreateSignature(machOContext, objSpan, signOptions, obj.Identifier, teamId, codeDirectoryFlags, segmentFlags, requirementsBytes, entitlementsXmlBytes, entitlementsDerBytes, resourcesBytes, infoBytes, null);
        }

        // Sign the resources
        return new BundleSignature(signatures, new AppBundleInfo { CodeResources = pList, CodeResourcesBytes = resourcesBytes });
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
        // FCS-002: Write the exact CodeResources bytes hashed into the executable's ResourceDir special slot.
        fs.Write(info.CodeResourcesBytes);

        // Write the signature(s) to the mach object file
        using FileAllocation file = new FileAllocation(obj.BundleExecutablePath);
        Span<byte> span = file.GetSpan();

        MachObject[] machObjects = MachObjectHelper.GetMachObjects(span);
        Debug.Assert(signature.Signatures.Length == machObjects.Length, "The number of signatures does not match the number of mach object slices.");

        MachObjectSignatureHelper.WriteSignatures(file, machObjects, signature.Signatures);
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
        ReadOnlySpan<byte> executable = allocation.GetSpan();
        MachObject[] objects = MachObjectHelper.GetMachObjects(executable);
        IFormatHandler machHandler = new MachObjectFormatHandler();
        bool hasSignature = false;
        foreach (MachObject machObject in objects)
        {
            if (machHandler.GetContext(machObject.GetSpan(executable)).IsSigned)
            {
                hasSignature = true;
                break;
            }
        }

        if (hasSignature)
        {
            RemoveMachSignatures(allocation, executable, objects, machHandler);
            removed |= SignatureComponent.MachObjectSignature;
        }

        return removed;
    }

    public bool HasValidSignature(IContext context)
    {
        AppBundleContext obj = (AppBundleContext)context;

        if (!obj.IsSigned)
            return false;

        // A CodeResources seal and every main-executable architecture are required for a complete bundle signature.
        if (!File.Exists(Path.Combine(obj.BundlePath, "Contents", "_CodeSignature", "CodeResources")))
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

                if (!objContext.IsSigned)
                    return false;

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

                try
                {
                    // FCS-001: Each bundle architecture must verify its detached CMS over its embedded CodeDirectory.
                    handler.CheckSignature(objContext, objSpan, signedCms);
                }
                catch (CryptographicException)
                {
                    return false;
                }

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
        string codeResourcesPath = Path.Combine(context.BundlePath, "Contents", "_CodeSignature", "CodeResources");
        byte[] codeResourcesBytes = File.ReadAllBytes(codeResourcesPath);

        // FCS-003: Trust the on-disk special-slot inputs only after matching their exact sealed bytes in every architecture.
        if (!VerifySpecialSlots(context, codeResourcesBytes, File.ReadAllBytes(Path.Combine(context.BundlePath, "Contents", "Info.plist"))))
            return false;

        // Deserialize the property list
        Dictionary<string, object> pList = PListSerializer.Deserialize(codeResourcesBytes);
        if (!pList.TryGetValue("files2", out object? filesObject) || filesObject is not Dictionary<string, object> files2 || !pList.TryGetValue("rules2", out object? rulesObject) || rulesObject is not Dictionary<string, object> rules2)
            return false;

        string contents = Path.Combine(context.BundlePath, "Contents");

        foreach (SealEntry entry in EnumerateSealableEntries(context, rules2))
        {
            string relativePath = entry.RelativePath;
            RuleDecision rule = EvaluateRule(rules2, relativePath);
            if (!rule.Matched || (entry.NestedCode != null && !rule.Nested))
                return false;

            if (rule.Omit)
                continue;

            if (!files2.TryGetValue(relativePath, out object? value))
                return false;

            if ((entry.NestedCode != null) != IsNestedEntry(value))
                return false;
        }

        foreach ((string relativePath, object value) in files2)
        {
            if (!ValidateFiles2Entry(contents, relativePath, value))
                return false;
        }

        return true;
    }

    private static bool ValidateFiles2Entry(string contentsRoot, string relativePath, object value)
    {
        if (!TryResolveBundleRelativePath(contentsRoot, relativePath, out string? fullPath))
            return false;

        if (value is byte[] hashBytes)
            return ValidateFileHash(fullPath, hashBytes, HashAlgorithmName.SHA256);

        if (value is not Dictionary<string, object> dict)
            throw new InvalidDataException($"Unsupported CodeResources entry type for '{relativePath}'.");

        if (dict.TryGetValue("cdhash", out object? cdHashObj) && cdHashObj is byte[] cdHash)
        {
            NestedCode? nested = TryResolveNestedCode(fullPath, Directory.Exists(fullPath));
            if (nested == null)
                return false;

            if (!dict.TryGetValue("requirement", out object? requirementObj) || requirementObj is not string requirement)
                return false;

            if (!ValidateExecutableCdHash(nested.ExecutablePath, cdHash, requirement))
                return false;

            // FCS-003: Nested bundles recurse; standalone nested Mach-O code must validate every architecture.
            return nested.IsBundle ? CodeSignProvider.FromBundle(nested.SealPath).HasValidSignature() : ValidateMachExecutable(nested.ExecutablePath);
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

    private static bool ValidateExecutableCdHash(string executablePath, byte[] expectedCdHash, string expectedRequirementText)
    {
        IFormatHandler formatHandler = new MachObjectFormatHandler();

        using FileAllocation allocation = new FileAllocation(executablePath);
        Span<byte> span = allocation.GetSpan();

        MachObject[] objs = MachObjectHelper.GetMachObjects(span);

        if (objs.Length == 0)
            return ValidateNestedSlice(formatHandler, span, expectedCdHash, expectedRequirementText, out bool matchesCdHash) && matchesCdHash;

        bool anyCdHashMatch = false;
        for (int i = 0; i < objs.Length; i++)
        {
            ReadOnlySpan<byte> objSpan = objs[i].GetSpan(span);
            if (!ValidateNestedSlice(formatHandler, objSpan, expectedCdHash, expectedRequirementText, out bool matchesCdHash))
                return false;
            anyCdHashMatch |= matchesCdHash;
        }

        return anyCdHashMatch;
    }

    private static bool ValidateNestedSlice(IFormatHandler handler, ReadOnlySpan<byte> objSpan, byte[] expectedCdHash, string expectedRequirementText, out bool matchesCdHash)
    {
        matchesCdHash = false;
        IContext machContext = handler.GetContext(objSpan);

        if (!machContext.IsSigned)
            return false;

        ReadOnlySpan<byte> signatureBytes = handler.ExtractSignature(machContext, objSpan);
        SignedCms signedCms = new SignedCms();
        signedCms.Decode(signatureBytes);

        try
        {
            handler.CheckSignature(machContext, objSpan, signedCms);
        }
        catch (CryptographicException)
        {
            return false;
        }

        if (!handler.ExtractHashFromSignedCms(signedCms, out byte[]? digest, out HashAlgorithmName algorithm) || !digest.SequenceEqual(handler.ComputeHash(machContext, objSpan, algorithm)))
            return false;

        if (!MachObjectFormatHandler.TryExtractSpecialSlot((MachOContext)machContext, objSpan, CsSlot.Requirements, out ReadOnlySpan<byte> requirements))
            return false;

        try
        {
            if (!string.Equals(Requirements.GetDesignatedRequirementText(requirements), expectedRequirementText, StringComparison.Ordinal))
                return false;
        }
        catch (InvalidDataException)
        {
            return false;
        }

        ReadOnlySpan<byte> cdHash = digest.Length > 20 ? digest.AsSpan(0, 20) : digest;
        matchesCdHash = cdHash.SequenceEqual(expectedCdHash);
        return true;
    }

    private static bool ValidateMachExecutable(string executablePath)
    {
        using FileAllocation allocation = new FileAllocation(executablePath);
        return ValidateMachData(allocation.GetSpan());
    }

    private static bool ValidateMachData(ReadOnlySpan<byte> span)
    {
        IFormatHandler handler = new MachObjectFormatHandler();

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

            try
            {
                handler.CheckSignature(machContext, objSpan, signedCms);
            }
            catch (CryptographicException)
            {
                return false;
            }

            if (!handler.ExtractHashFromSignedCms(signedCms, out byte[]? expectedDigest, out HashAlgorithmName algo))
                return false;

            byte[] actualDigest = handler.ComputeHash(machContext, objSpan, algo);
            return expectedDigest.SequenceEqual(actualDigest);
        }
    }

    private static Dictionary<string, object> BuildPList(AppBundleContext obj, X509Certificate2 certificate)
    {
        Dictionary<string, object> files = new Dictionary<string, object>(StringComparer.Ordinal);
        Dictionary<string, object> files2 = new Dictionary<string, object>(StringComparer.Ordinal);
        Dictionary<string, object> rules = BuildRules();
        Dictionary<string, object> rules2 = BuildRules2();

        foreach (SealEntry sealEntry in EnumerateSealableEntries(obj, rules2))
        {
            string relative = sealEntry.RelativePath;
            string entry = sealEntry.FullPath;
            if (EvaluateRule(rules2, relative).Omit)
                continue;

            if (sealEntry.NestedCode != null)
            {
                NestedCode nested = sealEntry.NestedCode;
                Requirements nestedRequirement = certificate.IsAppleDeveloperCertificate()
                    ? Requirements.CreateAppleDevDefault(nested.Identifier, certificate)
                    : Requirements.CreateDefault(nested.Identifier, certificate);

                files2.Add(relative, new Dictionary<string, object>
                {
                    { "cdhash", GetExecutableCdHash(nested.ExecutablePath) },
                    // FCS-002/FCS-003: This text corresponds byte-for-byte to the designated requirement retained or generated for nested code.
                    { "requirement", nestedRequirement.GetDesignatedRequirementText() }
                });
                continue;
            }

            FileAttributes attrs = File.GetAttributes(entry);
            bool isDir = (attrs & FileAttributes.Directory) != FileAttributes.None;
            bool isReparse = (attrs & FileAttributes.ReparsePoint) != FileAttributes.None;
            Dictionary<string, object> files2Value = new Dictionary<string, object>(1);

            if (isReparse)
            {
                FileSystemInfo fsi = isDir ? new DirectoryInfo(entry) : new FileInfo(entry);
                files2Value.Add("symlink", fsi.LinkTarget ?? throw new InvalidDataException($"Unable to resolve symlink target for '{relative}'."));
            }
            else
            {
                using FileStream fs = File.OpenRead(entry);
                files2Value.Add("hash2", SHA256.HashData(fs));

                if (!EvaluateRule(rules, relative).Omit && Regex.IsMatch(relative, @"^(Resources/|version\.plist$)", RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture, RegexTimeout))
                {
                    fs.Position = 0;
                    files.Add(relative, SHA1.HashData(fs));
                }
            }

            files2.Add(relative, files2Value);
        }

        // FCS-002: A v2 CodeResources envelope carries both legacy and modern seals plus their evaluation rules.
        return new Dictionary<string, object>
        {
            { "files", files },
            { "files2", files2 },
            { "rules", rules },
            { "rules2", rules2 }
        };
    }

    private static void SignNestedCode(AppBundleContext context, SignOptions signOptions, Dictionary<string, object> rules2, string? teamId, MachObjectSigningFlags signingFlags)
    {
        foreach (NestedCode nested in EnumerateSealableEntries(context, rules2).Select(entry => entry.NestedCode).OfType<NestedCode>())
        {
            if (!PathHelper.IsPhysicalPathWithin(nested.ExecutablePath, context.BundlePath))
                throw new InvalidDataException($"Nested executable '{nested.ExecutablePath}' resolves outside the bundle.");

            if (!nested.IsBundle)
            {
                SignMachExecutable(nested, signOptions, teamId, signingFlags);
                continue;
            }

            CodeSignBundleProvider provider = CodeSignProvider.FromBundle(nested.SealPath);
            AppBundleContext nestedContext = AppBundleContext.Create(nested.SealPath);

            if (nestedContext.IsSigned)
                provider.RemoveSignature();

            BundleSignature signature = provider.CreateSignature(signOptions, new AppBundleOptions { TeamId = teamId, SigningFlags = signingFlags });
            provider.WriteSignature(signature);
        }
    }

    private static void SignMachExecutable(NestedCode nested, SignOptions signOptions, string? teamId, MachObjectSigningFlags signingFlags)
    {
        IFormatHandler handler = new MachObjectFormatHandler();
        using FileAllocation allocation = new FileAllocation(nested.ExecutablePath);
        ReadOnlySpan<byte> data = allocation.GetSpan();
        MachObject[] machObjects = MachObjectHelper.GetMachObjects(data);
        bool anySigned = false;
        foreach (MachObject machObject in machObjects)
        {
            bool isSigned = handler.GetContext(machObject.GetSpan(data)).IsSigned;
            anySigned |= isSigned;
        }

        Requirements requirements = CreateRequirements(nested.Identifier, signOptions.Certificate);
        byte[] requirementBytes = requirements.ToArray();

        if (anySigned)
        {
            // Parent re-signing also re-signs nested code, propagating its requested identity and flags.
            RemoveMachSignatures(allocation, data, machObjects, handler);
            data = allocation.GetSpan();
            machObjects = MachObjectHelper.GetMachObjects(data);
        }

        Signature[] signatures = new Signature[machObjects.Length];

        for (int i = 0; i < machObjects.Length; i++)
        {
            ReadOnlySpan<byte> slice = machObjects[i].GetSpan(data);
            MachOContext machContext = (MachOContext)handler.GetContext(slice);
            signatures[i] = MachObjectFormatHandler.CreateSignature(machContext, slice, signOptions, nested.Identifier, teamId, MachObjectFormatHandler.GetCodeDirectoryFlags(signingFlags), ExecSegFlags.MainBinary, requirementBytes, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, null);
        }

        MachObjectSignatureHelper.WriteSignatures(allocation, machObjects, signatures);
    }

    private static Requirements CreateRequirements(string identifier, X509Certificate2 certificate) => certificate.IsAppleDeveloperCertificate()
        ? Requirements.CreateAppleDevDefault(identifier, certificate)
        : Requirements.CreateDefault(identifier, certificate);

    private static void RemoveMachSignatures(FileAllocation allocation, ReadOnlySpan<byte> data, MachObject[] machObjects, IFormatHandler handler)
    {
        MachMagic magic = (MachMagic)ReadUInt32BigEndian(data);
        if (magic is not (MachMagic.FatMagicBE or MachMagic.FatMagicLE or MachMagic.FatMagic64BE or MachMagic.FatMagic64LE))
        {
            Span<byte> slice = allocation.GetSpan();
            IContext context = handler.GetContext(slice);
            if (context.IsSigned)
            {
                long delta = handler.RemoveSignature(context, slice);
                allocation.SetLength(checked((uint)(slice.Length - delta)));
            }
            return;
        }

        MachObjectSignatureHelper.RemoveSignatures(allocation, machObjects);
    }

    private static void RemoveMachSignatures(string executablePath)
    {
        using FileAllocation allocation = new FileAllocation(executablePath);
        ReadOnlySpan<byte> data = allocation.GetSpan();
        RemoveMachSignatures(allocation, data, MachObjectHelper.GetMachObjects(data), new MachObjectFormatHandler());
    }

    private static NestedCode? TryResolveNestedCode(string path, bool isDirectory)
    {
        if (!isDirectory)
            return IsMachObjectFile(path) ? new NestedCode(path, path, Path.GetFileName(path), false) : null;

        if (IsNestedBundle(path))
        {
            AppBundleContext context = AppBundleContext.Create(path);
            return new NestedCode(path, context.BundleExecutablePath, context.Identifier, true);
        }

        string[] infoCandidates =
        [
            Path.Combine(path, "Resources", "Info.plist"),
            Path.Combine(path, "Versions", "Current", "Resources", "Info.plist"),
            Path.Combine(path, "Versions", "A", "Resources", "Info.plist"),
            Path.Combine(path, "Info.plist")
        ];

        string identifier = Path.GetFileNameWithoutExtension(path);
        string executableName = identifier;
        foreach (string infoPath in infoCandidates)
        {
            if (!File.Exists(infoPath))
                continue;

            Dictionary<string, object> info = PListSerializer.Deserialize(File.ReadAllBytes(infoPath));
            if (info.TryGetValue("CFBundleIdentifier", out object? identifierValue) && identifierValue is string bundleIdentifier)
                identifier = bundleIdentifier;
            if (info.TryGetValue("CFBundleExecutable", out object? executableValue) && executableValue is string bundleExecutable)
                executableName = bundleExecutable;
            break;
        }

        string[] executableCandidates =
        [
            Path.Combine(path, executableName),
            Path.Combine(path, "Versions", "Current", executableName),
            Path.Combine(path, "Versions", "A", executableName)
        ];

        foreach (string executablePath in executableCandidates)
        {
            if (IsMachObjectFile(executablePath))
                return new NestedCode(path, executablePath, identifier, false);
        }

        return null;
    }

    private static bool IsMachObjectFile(string path)
    {
        if (!File.Exists(path))
            return false;

        Span<byte> magicBytes = stackalloc byte[4];
        using FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Read(magicBytes) != magicBytes.Length)
            return false;

        MachMagic magic = (MachMagic)ReadUInt32BigEndian(magicBytes);
        return magic is MachMagic.MachMagicBE or MachMagic.MachMagicLE or MachMagic.MachMagic64BE or MachMagic.MachMagic64LE or MachMagic.FatMagicBE or MachMagic.FatMagicLE or MachMagic.FatMagic64BE or MachMagic.FatMagic64LE;
    }

    private static IEnumerable<SealEntry> EnumerateSealableEntries(AppBundleContext context, Dictionary<string, object> rules2)
    {
        string contents = Path.Combine(context.BundlePath, "Contents");
        string executable = NormalizeRelativePath(Path.GetRelativePath(contents, context.BundleExecutablePath));
        Stack<string> directories = new Stack<string>();
        directories.Push(contents);

        while (directories.Count != 0)
        {
            string directory = directories.Pop();
            foreach (string entry in Directory.EnumerateFileSystemEntries(directory).Order(StringComparer.Ordinal))
            {
                string relative = NormalizeRelativePath(Path.GetRelativePath(contents, entry));
                if (relative == executable || relative == "CodeResources" || relative == "_CodeSignature" || relative.StartsWith("_CodeSignature/", StringComparison.Ordinal))
                    continue;

                FileAttributes attrs = File.GetAttributes(entry);
                bool isDirectory = (attrs & FileAttributes.Directory) != FileAttributes.None;
                bool isReparse = (attrs & FileAttributes.ReparsePoint) != FileAttributes.None;
                RuleDecision rule = EvaluateRule(rules2, relative);
                // Framework-style directories are traversed so their resources remain covered by this bundle's seal.
                NestedCode? nested = !isReparse && rule.Nested ? TryResolveNestedCode(entry, isDirectory) : null;

                if (nested != null || !isDirectory || isReparse)
                    yield return new SealEntry(relative, entry, nested);
                else
                    directories.Push(entry);
            }
        }
    }

    private static bool VerifySpecialSlots(AppBundleContext context, byte[] codeResources, byte[] infoPlist)
    {
        IFormatHandler handler = new MachObjectFormatHandler();
        using FileAllocation allocation = new FileAllocation(context.BundleExecutablePath);
        ReadOnlySpan<byte> data = allocation.GetSpan();

        foreach (MachObject machObject in MachObjectHelper.GetMachObjects(data))
        {
            ReadOnlySpan<byte> slice = machObject.GetSpan(data);
            MachOContext machContext = (MachOContext)handler.GetContext(slice);

            if (!MachObjectFormatHandler.VerifySpecialSlot(machContext, slice, CsSlot.ResourceDir, codeResources))
                return false;

            if (!MachObjectFormatHandler.VerifySpecialSlot(machContext, slice, CsSlot.Info, infoPlist))
                return false;
        }

        return true;
    }

    private static byte[] GetExecutableCdHash(string executablePath)
    {
        IFormatHandler handler = new MachObjectFormatHandler();
        using FileAllocation allocation = new FileAllocation(executablePath);
        ReadOnlySpan<byte> data = allocation.GetSpan();
        MachObject machObject = MachObjectHelper.GetMachObjects(data)[0];
        ReadOnlySpan<byte> slice = machObject.GetSpan(data);
        IContext machContext = handler.GetContext(slice);
        SignedCms cms = new SignedCms();
        cms.Decode(handler.ExtractSignature(machContext, slice));

        if (!handler.ExtractHashFromSignedCms(cms, out byte[]? digest, out _))
            throw new InvalidDataException("The nested bundle CMS does not contain a CodeDirectory hash.");

        return digest.AsSpan(0, Math.Min(20, digest.Length)).ToArray();
    }

    private static Dictionary<string, object> BuildRules() => new Dictionary<string, object>(StringComparer.Ordinal)
    {
        { @"^Resources/", true },
        { @"^Resources/.*\.lproj/", new Dictionary<string, object> { { "optional", true }, { "weight", 1000.0 } } },
        { @"^Resources/.*\.lproj/locversion\.plist$", new Dictionary<string, object> { { "omit", true }, { "weight", 1100.0 } } },
        { @"^Resources/Base\.lproj/", new Dictionary<string, object> { { "weight", 1010.0 } } },
        { @"^version\.plist$", true }
    };

    private static Dictionary<string, object> BuildRules2() => new Dictionary<string, object>(StringComparer.Ordinal)
    {
        { @"^.*", true },
        { @".*\.dSYM($|/)", new Dictionary<string, object> { { "weight", 11.0 } } },
        { @"^(.*/)?\.DS_Store$", new Dictionary<string, object> { { "omit", true }, { "weight", 2000.0 } } },
        { @"^(Frameworks|SharedFrameworks|PlugIns|Plug-ins|XPCServices|Helpers|MacOS|Library/(Automator|Spotlight|LoginItems))/", new Dictionary<string, object> { { "nested", true }, { "weight", 10.0 } } },
        { @"^[^/]+$", new Dictionary<string, object> { { "nested", true }, { "weight", 10.0 } } },
        { @"^embedded\.provisionprofile$", new Dictionary<string, object> { { "weight", 20.0 } } },
        { @"^Info\.plist$", new Dictionary<string, object> { { "omit", true }, { "weight", 20.0 } } },
        { @"^PkgInfo$", new Dictionary<string, object> { { "omit", true }, { "weight", 20.0 } } },
        { @"^Resources/", new Dictionary<string, object> { { "weight", 20.0 } } },
        { @"^Resources/.*\.lproj/", new Dictionary<string, object> { { "optional", true }, { "weight", 1000.0 } } },
        { @"^Resources/.*\.lproj/locversion\.plist$", new Dictionary<string, object> { { "omit", true }, { "weight", 1100.0 } } },
        { @"^Resources/Base\.lproj/", new Dictionary<string, object> { { "weight", 1010.0 } } },
        { @"^version\.plist$", new Dictionary<string, object> { { "weight", 20.0 } } }
    };

    private static RuleDecision EvaluateRule(Dictionary<string, object> rules, string relativePath)
    {
        RuleDecision result = default;
        double selectedWeight = double.NegativeInfinity;

        foreach ((string pattern, object value) in rules)
        {
            bool matches;
            try
            {
                matches = Regex.IsMatch(relativePath, pattern, RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture, RegexTimeout);
            }
            catch (ArgumentException)
            {
                return new RuleDecision(false, false, false);
            }

            if (!matches)
                continue;

            Dictionary<string, object>? options = value as Dictionary<string, object>;
            double weight = options != null && options.TryGetValue("weight", out object? weightValue) ? Convert.ToDouble(weightValue) : 0;
            if (weight < selectedWeight)
                continue;

            selectedWeight = weight;
            result = new RuleDecision(true, options?.TryGetValue("omit", out object? omit) == true && omit is true, options?.TryGetValue("nested", out object? nested) == true && nested is true);
        }

        return result;
    }

    private static bool IsNestedEntry(object value) => value is Dictionary<string, object> dict && dict.TryGetValue("cdhash", out object? cdhash) && cdhash is byte[];

    private static bool IsNestedBundle(string path) => File.Exists(Path.Combine(path, "Contents", "Info.plist"));

    private static bool TryResolveBundleRelativePath(string root, string relativePath, [NotNullWhen(true)]out string? fullPath)
    {
        fullPath = null;
        if (string.IsNullOrEmpty(relativePath) || Path.IsPathRooted(relativePath))
            return false;

        string normalizedRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        string candidate = Path.GetFullPath(Path.Combine(normalizedRoot, relativePath.Replace('/', Path.DirectorySeparatorChar)));
        StringComparison comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        if (!candidate.StartsWith(normalizedRoot + Path.DirectorySeparatorChar, comparison))
            return false;

        fullPath = candidate;
        return true;
    }

    private static byte[] SerializePList(Dictionary<string, object> pList)
    {
        using MemoryStream stream = new MemoryStream();
        PListSerializer.Serialize(pList, stream);
        return stream.ToArray();
    }

    private static string NormalizeRelativePath(string path) => path.Replace(Path.DirectorySeparatorChar, '/').Replace(Path.AltDirectorySeparatorChar, '/');

    private readonly record struct RuleDecision(bool Matched, bool Omit, bool Nested);

    private sealed record NestedCode(string SealPath, string ExecutablePath, string Identifier, bool IsBundle);

    private sealed record SealEntry(string RelativePath, string FullPath, NestedCode? NestedCode);

    private sealed class AppBundleInfo
    {
        internal required Dictionary<string, object> CodeResources { get; init; }
        internal required byte[] CodeResourcesBytes { get; init; }
    }
}