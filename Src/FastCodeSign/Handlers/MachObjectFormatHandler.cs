using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Genbox.FastCodeSign.Abstracts;
using Genbox.FastCodeSign.Extensions;
using Genbox.FastCodeSign.Internal;
using Genbox.FastCodeSign.Internal.Extensions;
using Genbox.FastCodeSign.Internal.Helpers;
using Genbox.FastCodeSign.Internal.MachObject;
using Genbox.FastCodeSign.Internal.MachObject.Headers;
using Genbox.FastCodeSign.Internal.MachObject.Headers.Enums;
using Genbox.FastCodeSign.MachObjects;
using Genbox.FastCodeSign.Models;
using static Genbox.FastCodeSign.Internal.MachObject.MachBinaryPrimitives;

namespace Genbox.FastCodeSign.Handlers;

/// <summary>
/// Supports macOS Mach Object files.
/// </summary>
public sealed class MachObjectFormatHandler : IFormatHandler
{
    // See https://github.com/aidansteele/osx-abi-macho-file-format-reference
    // - Requirements: https://developer.apple.com/documentation/technotes/tn3127-inside-code-signing-requirements
    // - Entitlements: https://developer.apple.com/documentation/bundleresources/entitlements
    // - Info.plist: https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/AboutInformationPropertyListFiles.html

    // Note: This is not byte-identical with macOS's CodeSign tool. Differences:
    // - It encodes in BER, not DER. (DER is preferred for crypto)
    // - It uses DER order of attributes (sorted by OID).
    // - It adds null parameters to digests (Legacy)

    private const int CmsSizeEst = 18_000;
    private const int PageSize = 4096;
    private const Supports UseVersion = Supports.SupportsExecSegment;

    public int MinValidSize => PageSize; // Since Yosemite 10.10.5 it must be at least PageSize. See https://github.com/apple-oss-distributions/xnu/blob/e3723e1f17661b24996789d8afc084c0c3303b26/bsd/kern/kern_exec.c#L873
    public string[] ValidExt => []; // Mach Objects usually don't have extensions

    public bool IsValidHeader(ReadOnlySpan<byte> data)
    {
        uint magic = ReadUInt32BigEndian(data);
        return magic is (uint)MachMagic.MachMagicBE or (uint)MachMagic.MachMagicLE or (uint)MachMagic.MachMagic64BE or (uint)MachMagic.MachMagic64LE;
    }

    IContext IFormatHandler.GetContext(ReadOnlySpan<byte> data) => MachOContext.Create(data);

    ReadOnlySpan<byte> IFormatHandler.ExtractSignature(IContext context, ReadOnlySpan<byte> data)
    {
        MachOContext obj = (MachOContext)context;
        Debug.Assert(obj.CodeSignature != null);

        if ((ulong)obj.CodeSignature.DataOffset + obj.CodeSignature.DataSize > (ulong)data.Length)
            throw new InvalidDataException("The code signature data is truncated.");

        //Read the SuperBlob
        ReadOnlySpan<byte> sbSpan = data.Slice((int)obj.CodeSignature.DataOffset, (int)obj.CodeSignature.DataSize);
        if (sbSpan.Length < SuperBlobHeader.StructSize)
            throw new InvalidDataException("The code signature superblob is truncated.");

        SuperBlobHeader sbHeader = SuperBlobHeader.Read(sbSpan);

        if (sbHeader.Magic != CsMagic.EmbeddedSignature || sbHeader.Count == 0) //Not embedded or there are no slots in the SuperBlob
            return ReadOnlySpan<byte>.Empty;

        if (sbHeader.Length < SuperBlobHeader.StructSize || sbHeader.Length > sbSpan.Length || (ulong)sbHeader.Count * BlobIndex.StructSize > sbHeader.Length - SuperBlobHeader.StructSize)
            throw new InvalidDataException("The code signature blob index is truncated.");

        sbSpan = sbSpan[..(int)sbHeader.Length];

        //Read the index structures right after the SuperBlob header
        for (int i = 0; i < sbHeader.Count; i++)
        {
            int indexOffset = SuperBlobHeader.StructSize + (i * BlobIndex.StructSize);
            if (indexOffset + BlobIndex.StructSize > sbSpan.Length)
                throw new InvalidDataException("The code signature blob index is truncated.");

            BlobIndex blobIndex = BlobIndex.Read(sbSpan[indexOffset..]);

            if (blobIndex.Type != CsSlot.Signature)
                continue;

            if (blobIndex.Offset > sbSpan.Length || (ulong)blobIndex.Offset + BlobWrapper.StructSize > (ulong)sbSpan.Length)
                throw new InvalidDataException("The code signature blob is truncated.");

            ReadOnlySpan<byte> blobSpan = sbSpan[(int)blobIndex.Offset..];
            BlobWrapper bh = BlobWrapper.Read(blobSpan);

            if (bh.Type != CsMagic.BlobWrapper) //Guard against corrupt files
                return ReadOnlySpan<byte>.Empty;

            if (bh.Length > blobSpan.Length)
                throw new InvalidDataException("The code signature blob is truncated.");

            // The CMS ASN1 is the payload of the wrapper
            return blobSpan.Slice(BlobWrapper.StructSize, (int)bh.Length - BlobWrapper.StructSize); //Length includes the header. We don't need the header.
        }

        return ReadOnlySpan<byte>.Empty; // We did not manage to find the CMS blob
    }

    byte[] IFormatHandler.ComputeHash(IContext context, ReadOnlySpan<byte> data, HashAlgorithmName hashAlgorithm)
    {
        MachOContext obj = (MachOContext)context;
        Debug.Assert(obj.CodeSignature != null);

        if ((ulong)obj.CodeSignature.DataOffset + obj.CodeSignature.DataSize > (ulong)data.Length)
            throw new InvalidDataException("The code signature data is truncated.");

        //If there is no signature, we cannot just hash the file, since Mach Object signatures require external files such as entitlement and requirements
        //We cannot require the caller to provide this data, so we simply tell them we are unable to hash unsigned files. That's what macOS's CodeSign does also.
        if (!obj.IsSigned)
            throw new InvalidOperationException("Mach Object does not support stable hashing");

        ReadOnlySpan<byte> cdSpan = GetEmbeddedBlob(obj, data, CsSlot.CodeDirectory);
        if (cdSpan.Length < CodeDirectoryHeader.StructSize)
            throw new InvalidDataException("The CodeDirectory is truncated.");

        //Read the CodeDirectory header
        uint hashOff = ReadUInt32BigEndian(cdSpan.Slice(16, 4));
        uint nSpecial = ReadUInt32BigEndian(cdSpan.Slice(24, 4));
        uint nCodeSlots = ReadUInt32BigEndian(cdSpan.Slice(28, 4));
        uint codeLimit32 = ReadUInt32BigEndian(cdSpan.Slice(32, 4));
        byte hashSize = cdSpan[36];
        byte hashType = cdSpan[37];
        byte pageSizeLg2 = cdSpan[39];

        if (GetHashType(hashAlgorithm) != hashType)
            throw new InvalidOperationException("Mismatch hash algorithm");

        //The CodeDirectory hash is of the entire blob. It consists of:
        //- The CodeDirectory header (static length)
        //- Version dependent headers (dynamic length)
        //- Identifier / team id
        //- Hashes of the special pages
        //- Hashes of the code pages

        if (hashSize == 0 || pageSizeLg2 >= 31)
            throw new InvalidDataException("The CodeDirectory contains invalid hash settings.");

        ulong specialHashesSize = (ulong)nSpecial * hashSize;
        if (hashOff < specialHashesSize || hashOff > cdSpan.Length)
            throw new InvalidDataException("The CodeDirectory contains invalid special hash offsets.");

        int specialHashOffset = checked((int)(hashOff - specialHashesSize));
        if (specialHashOffset < CodeDirectoryHeader.StructSize || (ulong)specialHashOffset + specialHashesSize > (ulong)cdSpan.Length)
            throw new InvalidDataException("The CodeDirectory contains invalid special hash offsets.");

        if ((ulong)hashOff + ((ulong)nCodeSlots * hashSize) > (ulong)cdSpan.Length)
            throw new InvalidDataException("The CodeDirectory contains invalid code hash offsets.");

        if (codeLimit32 > data.Length || nCodeSlots != ((ulong)codeLimit32 + ((1U << pageSizeLg2) - 1)) >> pageSizeLg2)
            throw new InvalidDataException("The CodeDirectory code limit is invalid.");

        //We create two hashers here. One to produce special/code page hashes, and one to consume the hashes which eventually become the CodeDirectory hash.
        HashAlgorithmName hashName = GetHashAlgorithmName(hashType);
        using IncrementalHash hasher = IncrementalHash.CreateHash(hashName);
        using IncrementalHash cdHasher = IncrementalHash.CreateHash(hashName);

        //The signed prefix ends immediately before the special-slot table.
        cdHasher.AppendData(cdSpan[..specialHashOffset]);

        //Then we go through the blobs, find special slots, and hash the content, then add the hash to cdHasher
        for (int i = checked((int)nSpecial); i > 0; i--)
        {
            ReadOnlySpan<byte> blobSpan;
            int specialIndex = (int)(nSpecial - i);

            try
            {
                blobSpan = GetEmbeddedBlob(obj, data, (CsSlot)i);
            }
            catch (InvalidOperationException)
            {
                cdHasher.AppendData(cdSpan.Slice(specialHashOffset + (specialIndex * hashSize), hashSize));
                continue;
            }

            hasher.AppendData(blobSpan);
            cdHasher.AppendData(hasher.GetHashAndReset().AsSpan(0, hashSize));
        }

        //Now we need to hash the file in <pageSize> chunks up to <codeLimit> and add the hashes to cdHasher
        uint pageSize = 1u << pageSizeLg2;

        ulong remaining = codeLimit32;
        int offset = 0;

        for (int slot = 0; slot < nCodeSlots; ++slot)
        {
            ulong thisPage = Math.Min(remaining, pageSize);
            hasher.AppendData(data.Slice(offset, (int)thisPage));
            cdHasher.AppendData(hasher.GetHashAndReset().AsSpan(0, hashSize));

            offset += (int)thisPage;
            remaining -= thisPage;
        }

        return cdHasher.GetHashAndReset();
    }

    long IFormatHandler.RemoveSignature(IContext context, Span<byte> data)
    {
        MachOContext obj = (MachOContext)context;
        Debug.Assert(obj.CodeSignature != null);

        //Remove the LC_CODE_SIGNATURE command from the list of load commands. It is the last command in the list.
        const uint size = LoadCommandHeader.StructSize + CodeSignatureHeader.StructSize;

        int expectedCodeSignatureOffset = checked((obj.Is64Bit ? 32 : 28) + (int)obj.MachHeader.SizeOfCommands - CodeSignatureHeader.StructSize);
        if (obj.LinkEdit.FileOffset > ulong.MaxValue - obj.LinkEdit.FileSize)
            throw new InvalidDataException("The __LINKEDIT section has invalid bounds.");

        ulong linkEditEnd = obj.LinkEdit.FileOffset + obj.LinkEdit.FileSize;
        ulong codeSignatureEnd = (ulong)obj.CodeSignature.DataOffset + obj.CodeSignature.DataSize;
        if (obj.CodeSignature.Offset != expectedCodeSignatureOffset)
            throw new InvalidDataException("The LC_CODE_SIGNATURE command must be the last load command to remove it safely.");
        if (obj.CodeSignature.DataOffset < obj.LinkEdit.FileOffset || obj.CodeSignature.DataSize > obj.LinkEdit.FileSize || codeSignatureEnd != linkEditEnd || linkEditEnd != (ulong)data.Length)
            throw new InvalidDataException("The code signature must be the final __LINKEDIT data to remove it safely.");

        //Clear the LC header and the LC_CODE_SIGNATURE command entry
        data.Slice(obj.CodeSignature.Offset - LoadCommandHeader.StructSize, (int)size).Clear();

        //Update Mach Object header
        bool le = obj.IsLittleEndian;
        WriteU32(data[16..], obj.MachHeader.NumberOfCommands - 1, le);
        WriteU32(data[20..], obj.MachHeader.SizeOfCommands - size, le);

        //Note: This leaves a 16-byte gap at the end of the load commands, but that's fine.

        //Shrink __LINKEDIT.filesize
        ulong newFileSize = obj.LinkEdit.FileSize - obj.CodeSignature.DataSize;

        if (obj.Is64Bit)
        {
            WriteU64(data[(obj.LinkEdit.Offset + 32)..], Align(newFileSize, 16384), le); // vmsize
            WriteU64(data[(obj.LinkEdit.Offset + 48)..], newFileSize, le); // filesize
        }
        else
        {
            WriteU32(data[(obj.LinkEdit.Offset + 28)..], (uint)Align(newFileSize, 16384), le); // vmsize
            WriteU32(data[(obj.LinkEdit.Offset + 36)..], (uint)newFileSize, le); // filesize
        }

        return obj.CodeSignature.DataSize;
    }

    void IFormatHandler.WriteSignature(IContext context, IAllocation allocation, Signature signature)
    {
        MachOContext obj = (MachOContext)context;

        ReadOnlySpan<byte> original = allocation.GetSpan();
        int oldSize = original.Length;
        MachObjectInfo info = (MachObjectInfo)signature.SignatureInfo!;

        ulong codeLimit = info.CodeLimit;
        int padLen = info.PaddingLength;
        uint sbSize = info.SuperBlockSize;

        SortedList<CsSlot, ReadOnlyMemory<byte>> blobs = new SortedList<CsSlot, ReadOnlyMemory<byte>>(info.Blobs); //We copy the collection to avoid duplicating the signature blob on multiple calls to WriteSignature
        byte[] cmsBytes = signature.SignedCms.Encode();
        blobs.Add(CsSlot.Signature, cmsBytes);

        uint requiredSize = checked((uint)(SuperBlobHeader.StructSize + BlobWrapper.StructSize + blobs.Sum(x => x.Value.Length + BlobIndex.StructSize)));
        // FCS-006: Capacity is validated before any persistent Mach-O header or allocation mutation.
        if (requiredSize > sbSize)
            throw new InvalidOperationException($"The encoded CMS requires {requiredSize} bytes, exceeding the reserved Mach-O signature capacity of {sbSize} bytes.");

        uint newSize = checked((uint)(oldSize + padLen + sbSize));
        byte[] staged = new byte[newSize];
        original.CopyTo(staged);
        WriteHeaders(staged, obj, codeLimit, padLen, sbSize);

        //Set the span at after the file where the SB begins
        Span<byte> data = staged.AsSpan(oldSize + padLen);

        // Write the SuperBlob header
        WriteUInt32BigEndian(data[..], (uint)CsMagic.EmbeddedSignature);
        WriteUInt32BigEndian(data[4..], (uint)(SuperBlobHeader.StructSize + blobs.Sum(x => x.Value.Length + BlobIndex.StructSize) + BlobWrapper.StructSize)); //The BlobWrapper is for the CMS blob
        WriteUInt32BigEndian(data[8..], (uint)blobs.Count);
        data = data[SuperBlobHeader.StructSize..];

        //Write all the SuperBlob payload headers
        int dataOffset = SuperBlobHeader.StructSize + (blobs.Count * BlobIndex.StructSize);
        foreach (KeyValuePair<CsSlot, ReadOnlyMemory<byte>> blob in blobs)
        {
            //Write a blob index
            WriteUInt32BigEndian(data, (uint)blob.Key);
            WriteUInt32BigEndian(data[4..], (uint)dataOffset);
            data = data[8..];
            dataOffset += blob.Value.Length;
        }

        //Write the payloads
        foreach (KeyValuePair<CsSlot, ReadOnlyMemory<byte>> blob in blobs)
        {
            // Wrap CMS in a blob wrapper. We do it here to avoid creating a buffer after encoding the CMS just to add a wrapper to the byte-array
            if (blob.Key == CsSlot.Signature)
            {
                WriteUInt32BigEndian(data, (uint)CsMagic.BlobWrapper);
                WriteUInt32BigEndian(data[4..], (uint)blob.Value.Length + 8);
                data = data[8..];
            }

            //Write the actual blob
            blob.Value.Span.CopyTo(data);
            data = data[blob.Value.Length..];
        }

        // FCS-006: Stage every fallible serialization step before growing or mutating the persistent allocation.
        try
        {
            allocation.SetLength(newSize);
            Span<byte> destination = allocation.GetSpan();
            if (destination.Length != staged.Length)
                throw new InvalidOperationException("The allocation did not grow to the requested Mach-O signature size.");

            staged.CopyTo(destination);
        }
        catch
        {
            try
            {
                allocation.SetLength((uint)oldSize);
            }
            catch
            {
                // IAllocation has no transaction primitive; preserve the original failure when rollback is unavailable.
            }

            throw;
        }
    }

    Signature IFormatHandler.CreateSignature(IContext context, ReadOnlySpan<byte> data, SignOptions signOptions, IFormatOptions? formatOptions, Action<CmsSigner>? configureSigner)
    {
        MachOContext obj = (MachOContext)context;
        MachObjectFormatOptions opt = formatOptions == null ? throw new InvalidOperationException("You must set format options with a valid identifier") : (MachObjectFormatOptions)formatOptions;

        string identifier = opt.Identifier;

        if (identifier == null!)
            throw new InvalidOperationException($"Identifier cannot be null. Please supply a filename or set the identifier directly on {nameof(MachObjectFormatHandler)}");

        Requirements? req = opt.Requirements;

        if (req == null)
            if (signOptions.Certificate.IsAppleDeveloperCertificate())
                req = Requirements.CreateAppleDevDefault(identifier, signOptions.Certificate);
            else
                req = Requirements.CreateDefault(identifier, signOptions.Certificate);

        byte[] requirementsBytes = req.ToArray();

        Entitlements? entitlements = opt.Entitlements;

        ExecSegFlags segmentFlags = ExecSegFlags.MainBinary;
        byte[]? entitlementsXmlBytes = null;
        byte[]? entitlementsDerBytes = null;

        if (entitlements != null)
        {
            segmentFlags |= GetExecSegFlags(entitlements);
            entitlementsXmlBytes = entitlements.EncodeAsXml();
            entitlementsDerBytes = entitlements.EncodeAsDer();
        }

        using MemoryStream ms = new MemoryStream();

        Dictionary<string, object>? resourceSeal = opt.ResourcesPropertyList;
        byte[]? resourcesBytes = null;

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

        string? teamId = opt.TeamId ?? (signOptions.Certificate.IsAppleDeveloperCertificate() ? signOptions.Certificate.GetTeamId() : null);
        return CreateSignature(obj, data, signOptions, identifier, teamId, GetCodeDirectoryFlags(opt.SigningFlags), segmentFlags, requirementsBytes, entitlementsXmlBytes, entitlementsDerBytes, resourcesBytes, infoBytes, configureSigner);
    }

    bool IFormatHandler.ExtractHashFromSignedCms(SignedCms signedCms, [NotNullWhen(true)]out byte[]? digest, out HashAlgorithmName algo)
    {
        digest = null;
        algo = default;

        if (signedCms.SignerInfos.Count == 0)
            return false;

        SignerInfo si = signedCms.SignerInfos[0]; //We assume a single signer

        CryptographicAttributeObject? attr = si.SignedAttributes
                                               .Cast<CryptographicAttributeObject>()
                                               .FirstOrDefault(a => a.Oid.Value == OidConstants.AppleHashAttrOid);

        if (attr is null || attr.Values.Count == 0)
            return false;

        AsnReader reader = new AsnReader(attr.Values[0].RawData, AsnEncodingRules.DER);
        AsnReader seq = reader.ReadSequence();
        algo = OidHelper.OidToHashAlgorithm(seq.ReadObjectIdentifier());
        digest = seq.ReadOctetString();
        return true;
    }

    void IFormatHandler.CheckSignature(IContext context, ReadOnlySpan<byte> data, SignedCms signedCms)
    {
        ReadOnlySpan<byte> codeDirectory = GetEmbeddedBlob((MachOContext)context, data, CsSlot.CodeDirectory);
        SignedCms detachedCms = new SignedCms(new ContentInfo(codeDirectory.ToArray()), true);
        detachedCms.Decode(signedCms.Encode());

        if (detachedCms.SignerInfos.Count == 0)
            throw new CryptographicException("The CMS does not contain a signer.");

        // FCS-001: Mach-O CMS signatures are detached and must verify over this exact embedded CodeDirectory blob.
        detachedCms.CheckSignature(true);
    }

    internal static bool TryExtractSpecialSlot(MachOContext context, ReadOnlySpan<byte> data, CsSlot slot, out ReadOnlySpan<byte> blob)
    {
        try
        {
            blob = GetEmbeddedBlob(context, data, slot);
            return true;
        }
        catch (InvalidOperationException)
        {
            blob = ReadOnlySpan<byte>.Empty;
            return false;
        }
    }

    internal static bool VerifySpecialSlot(MachOContext context, ReadOnlySpan<byte> data, CsSlot slot, ReadOnlySpan<byte> value)
    {
        ReadOnlySpan<byte> codeDirectory = GetEmbeddedBlob(context, data, CsSlot.CodeDirectory);
        if (codeDirectory.Length < CodeDirectoryHeader.StructSize)
            throw new InvalidDataException("The CodeDirectory is truncated.");

        uint hashOffset = ReadUInt32BigEndian(codeDirectory[16..]);
        uint specialSlotCount = ReadUInt32BigEndian(codeDirectory[24..]);
        byte hashSize = codeDirectory[36];
        byte hashType = codeDirectory[37];
        uint slotIndex = (uint)slot;

        if (slotIndex == 0 || slotIndex > specialSlotCount || hashSize == 0 || hashOffset < slotIndex * hashSize)
            return false;

        int slotOffset = checked((int)(hashOffset - (slotIndex * hashSize)));
        if (slotOffset > codeDirectory.Length - hashSize)
            throw new InvalidDataException("The CodeDirectory special-slot hashes are truncated.");

        using IncrementalHash hasher = IncrementalHash.CreateHash(GetHashAlgorithmName(hashType));
        hasher.AppendData(value);
        byte[] actualHash = hasher.GetHashAndReset();
        // FCS-003: External special-slot inputs are accepted only when their bytes reproduce the stored CodeDirectory hash.
        return codeDirectory.Slice(slotOffset, hashSize).SequenceEqual(actualHash.AsSpan(0, hashSize));
    }

    private static ReadOnlySpan<byte> GetEmbeddedBlob(MachOContext context, ReadOnlySpan<byte> data, CsSlot slot)
    {
        if (context.CodeSignature == null)
            throw new InvalidOperationException("The Mach Object is not signed.");

        ulong offset = context.CodeSignature.DataOffset;
        ulong size = context.CodeSignature.DataSize;
        if (offset > (ulong)data.Length || size > (ulong)data.Length - offset || size < SuperBlobHeader.StructSize)
            throw new InvalidDataException("The code signature superblob is truncated.");

        ReadOnlySpan<byte> superBlob = data.Slice((int)offset, (int)size);
        SuperBlobHeader header = SuperBlobHeader.Read(superBlob);
        if (header.Magic != CsMagic.EmbeddedSignature || header.Length > superBlob.Length || header.Length < SuperBlobHeader.StructSize)
            throw new InvalidDataException("The code signature superblob is invalid.");

        ulong indexLength = (ulong)header.Count * BlobIndex.StructSize;
        if (indexLength > header.Length - SuperBlobHeader.StructSize)
            throw new InvalidDataException("The code signature blob index is truncated.");

        superBlob = superBlob[..(int)header.Length];
        for (int i = 0; i < header.Count; i++)
        {
            BlobIndex index = BlobIndex.Read(superBlob[(SuperBlobHeader.StructSize + (i * BlobIndex.StructSize))..]);
            if (index.Type != slot)
                continue;

            if (index.Offset > superBlob.Length || (ulong)index.Offset + BlobWrapper.StructSize > (ulong)superBlob.Length)
                throw new InvalidDataException("The code signature blob is truncated.");

            ReadOnlySpan<byte> candidate = superBlob[(int)index.Offset..];
            BlobWrapper blobHeader = BlobWrapper.Read(candidate);
            if (blobHeader.Length < BlobWrapper.StructSize || blobHeader.Length > candidate.Length)
                throw new InvalidDataException("The code signature blob is truncated.");

            if (slot == CsSlot.CodeDirectory && blobHeader.Type != CsMagic.CodeDirectory)
                throw new InvalidDataException("The CodeDirectory blob has invalid magic.");

            return candidate[..(int)blobHeader.Length];
        }

        throw new InvalidOperationException($"The Mach-O signature does not contain slot {slot}.");
    }

    internal static Signature CreateSignature(MachOContext context, ReadOnlySpan<byte> data, SignOptions signOptions, string identifier, string? teamId, CdFlags codeDirectoryFlags, ExecSegFlags segFlags, ReadOnlyMemory<byte> requirements, ReadOnlyMemory<byte> entitlementsXml, ReadOnlyMemory<byte> entitlementsDer, ReadOnlyMemory<byte> resources, ReadOnlyMemory<byte> info, Action<CmsSigner>? configureSigner)
    {
        if (identifier == null!)
            throw new ArgumentNullException(nameof(identifier), $"Identifier cannot be null. Please supply a filename or set the identifier directly on {nameof(MachObjectFormatHandler)}");

        //Build the SuperBlob
        SortedList<CsSlot, ReadOnlyMemory<byte>> blobs = new SortedList<CsSlot, ReadOnlyMemory<byte>>();

        if (!requirements.IsEmpty)
            blobs.Add(CsSlot.Requirements, requirements);

        if (!entitlementsDer.IsEmpty)
            blobs.Add(CsSlot.EntitlementsDer, entitlementsDer);

        if (!entitlementsXml.IsEmpty)
            blobs.Add(CsSlot.Entitlements, entitlementsXml);

        SortedList<CsSlot, ReadOnlyMemory<byte>> specialSlots = new SortedList<CsSlot, ReadOnlyMemory<byte>>(blobs);
        if (!resources.IsEmpty)
            specialSlots.Add(CsSlot.ResourceDir, resources);

        if (!info.IsEmpty)
            specialSlots.Add(CsSlot.Info, info);

        // FCS-002: Info.plist and CodeResources are external special-slot inputs, not embedded SuperBlob payloads.
        int maxSlot = specialSlots.Count == 0 ? 0 : specialSlots.Max(x => (int)x.Key);

        ulong linkEditEnd = context.LinkEdit.FileOffset + context.LinkEdit.FileSize;
        Debug.Assert((uint)linkEditEnd == data.Length);

        ulong codeLimit = Align(linkEditEnd, 16); // Start of SuperBlob (16 byte aligned)
        HashAlgorithmName hashAlgo = signOptions.HashAlgorithm;
        int cdSize = GetCodeDirectorySize(hashAlgo, identifier, teamId, codeLimit, maxSlot, out int idOffset, out int teamIdOffset, out int hashesOffset);

        byte[] cdBlob = new byte[cdSize];
        blobs.Add(CsSlot.CodeDirectory, cdBlob);

        Span<byte> cdSpan = cdBlob.AsSpan();
        WriteCodeDirectoryHeader(ref cdSpan, identifier, teamId, hashAlgo, maxSlot, codeLimit, context.Text, codeDirectoryFlags, segFlags, cdSize, idOffset, teamIdOffset, hashesOffset);

        uint sbSize = Align((uint)(SuperBlobHeader.StructSize // SuperBlob header size
                                   + BlobWrapper.StructSize + CmsSizeEst //CMS wrapper header size + estimated cms size
                                   + blobs.Sum(x => x.Value.Length + BlobIndex.StructSize)), 16); //Size of all the blobs

        //We need to update the header etc. before adding the CodeDirectory as it calculates page hashes, and they otherwise won't be correct.
        //Create a temporary storage for patching the header (paged aligned to make things easier down the road)

        //The length is headerSize + sizeOfCommands + loadCommandHeaderSize + codeSignatureHeaderSize
        byte[] patch = new byte[Align((uint)((context.Is64Bit ? 32 : 28) + context.MachHeader.SizeOfCommands + LoadCommandHeader.StructSize + CodeSignatureHeader.StructSize), PageSize)];
        data[..patch.Length].CopyTo(patch);
        data = data[patch.Length..]; //Advance data by the page size

        int padLen = checked((int)(codeLimit - linkEditEnd));
        WriteHeaders(patch, context, codeLimit, padLen, sbSize);

        byte[] cdHash;
        using (IncrementalHash hasher = IncrementalHash.CreateHash(hashAlgo))
        {
            byte hashSize = hashAlgo.GetSize();

            HashSpecialSlots(ref cdSpan, specialSlots, maxSlot, hasher, hashSize);
            HashCodeSlotsPatch(ref cdSpan, patch, hasher, hashSize);
            HashCodeSlots(cdSpan, data, padLen, codeLimit - (ulong)patch.Length, hasher, hashSize);

            hasher.AppendData(cdBlob);
            cdHash = hasher.GetHashAndReset();
        }

        X509Certificate2 cert = signOptions.Certificate;
        using X509Chain chain = new X509Chain();
        X509ChainPolicy chainPolicy = new X509ChainPolicy { TrustMode = X509ChainTrustMode.CustomRootTrust };
        chainPolicy.CustomTrustStore.Add(cert); //We add itself because it might be self-signed

        foreach (X509Certificate2 appleCert in GetCerts())
            chainPolicy.CustomTrustStore.Add(appleCert);

        chain.ChainPolicy = chainPolicy;

        if (!chain.Build(cert) && !Array.TrueForAll(chain.ChainStatus, s => s.Status is X509ChainStatusFlags.InvalidExtension or X509ChainStatusFlags.HasNotSupportedCriticalExtension))
            throw new InvalidOperationException("Unable to build certificate chain");

        CmsSigner signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, cert, signOptions.PrivateKey)
        {
            DigestAlgorithm = hashAlgo.ToOid(),
            IncludeOption = X509IncludeOption.None
        };

        signer.Certificates.AddRange(chain.ChainElements.Select(x => x.Certificate).ToArray());
        signer.SignedAttributes.Add(new Pkcs9SigningTime());

        signer.SignedAttributes.Add(MakeAttribute(OidConstants.AppleHashAttrOid,
            EncodeSeq(hashAlgo.ToOidString(), cdHash)));

        signer.SignedAttributes.Add(MakeAttribute(OidConstants.ApplePListAttrOid,
            EncodeString(Encoding.UTF8.GetBytes(
                $"""
                     <?xml version="1.0" encoding="UTF-8"?>
                     <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
                     <plist version="1.0">
                     <dict>
                         <key>cdhashes</key>
                         <array>
                             <data>
                             {Convert.ToBase64String(cdHash.AsSpan(0, 20))}
                             </data>
                         </array>
                     </dict>
                     </plist>

                     """.Replace("    ", "\t", StringComparison.Ordinal).ReplaceLineEndings("\n")))));

        configureSigner?.Invoke(signer);

        ContentInfo contentInfo = new ContentInfo(cdBlob);
        SignedCms signed = new SignedCms(contentInfo, true);
        signed.ComputeSignature(signer, signOptions.Silent);

        return new Signature(signed, new MachObjectInfo
        {
            SuperBlockSize = sbSize,
            CodeLimit = codeLimit,
            PaddingLength = padLen,
            Blobs = blobs
        });

        static CryptographicAttributeObject MakeAttribute(string oid, byte[] derValue) => new CryptographicAttributeObject(new Oid(oid), new AsnEncodedDataCollection { new AsnEncodedData(oid, derValue) });

        static byte[] EncodeSeq(string oid, ReadOnlySpan<byte> octets)
        {
            AsnWriter w = new AsnWriter(AsnEncodingRules.DER);
            using (w.PushSequence())
            {
                w.WriteObjectIdentifier(oid);
                w.WriteOctetString(octets);
            }
            return w.Encode();
        }

        static byte[] EncodeString(ReadOnlySpan<byte> value)
        {
            AsnWriter w = new AsnWriter(AsnEncodingRules.DER);
            w.WriteOctetString(value);
            return w.Encode();
        }
    }

    internal static ExecSegFlags GetExecSegFlags(Entitlements entitlements)
    {
        ExecSegFlags flags = ExecSegFlags.MainBinary;
        // FCS-005: ExecSeg permissions require the exact case-sensitive entitlement key with boolean true.
        if (entitlements.IsEnabled("get-task-allow")) flags |= ExecSegFlags.AllowUnsigned;
        if (entitlements.IsEnabled("run-unsigned-code")) flags |= ExecSegFlags.AllowUnsigned;
        if (entitlements.IsEnabled("com.apple.private.cs.debugger")) flags |= ExecSegFlags.Debugger;
        if (entitlements.IsEnabled("dynamic-codesigning")) flags |= ExecSegFlags.Jit;
        if (entitlements.IsEnabled("com.apple.private.skip-library-validation")) flags |= ExecSegFlags.SkipLibraryValidation;
        if (entitlements.IsEnabled("com.apple.private.amfi.can-load-cdhash")) flags |= ExecSegFlags.CanLoadCdHash;
        if (entitlements.IsEnabled("com.apple.private.amfi.can-execute-cdhash")) flags |= ExecSegFlags.CanExecuteCdHash;

        return flags;
    }

    internal static CdFlags GetCodeDirectoryFlags(MachObjectSigningFlags flags) => flags switch
    {
        MachObjectSigningFlags.None => CdFlags.None,
        MachObjectSigningFlags.HardenedRuntime => CdFlags.Runtime,
        _ => throw new ArgumentOutOfRangeException(nameof(flags))
    };

    private static void WriteHeaders(Span<byte> span, MachOContext obj, ulong codeLimit, int padLength, uint sbSize)
    {
        bool le = obj.IsLittleEndian;

        // We need to insert the new load command right after the header
        int headerSize = obj.Is64Bit ? 32 : 28;
        int headerEnd = headerSize + (int)obj.MachHeader.SizeOfCommands;
        const int commandSize = LoadCommandHeader.StructSize + CodeSignatureHeader.StructSize;

        if (headerEnd > span.Length - commandSize)
            throw new InvalidDataException("The Mach Object does not have enough header padding for a code signature load command.");

        foreach (byte value in span.Slice(headerEnd, commandSize))
            if (value != 0)
                throw new InvalidDataException("The Mach Object does not have enough header padding for a code signature load command.");

        // Bump counts in the mach object header
        WriteU32(span[16..], obj.MachHeader.NumberOfCommands + 1, le);
        WriteU32(span[20..], obj.MachHeader.SizeOfCommands + commandSize, le);

        //Write CodeSignature
        WriteU32(span[(headerEnd + 0)..], (uint)LoadCommandType.CODE_SIGNATURE, le);
        WriteU32(span[(headerEnd + 4)..], commandSize, le);
        WriteU32(span[(headerEnd + 8)..], (uint)codeLimit, le); //Offset
        WriteU32(span[(headerEnd + 12)..], sbSize, le); //Length

        //Update LinkEdit header with new size
        ulong newLinkEditSize = obj.LinkEdit.FileSize + (uint)padLength + sbSize;

        if (obj.Is64Bit)
        {
            WriteU64(span[(obj.LinkEdit.Offset + 32)..], Align(newLinkEditSize, 16384), le); // vmsize
            WriteU64(span[(obj.LinkEdit.Offset + 48)..], newLinkEditSize, le); // filesize
        }
        else
        {
            WriteU32(span[(obj.LinkEdit.Offset + 28)..], checked((uint)Align(newLinkEditSize, 16384)), le); // vmsize
            WriteU32(span[(obj.LinkEdit.Offset + 36)..], checked((uint)newLinkEditSize), le); // filesize
        }
    }

    private static void WriteCodeDirectoryHeader(ref Span<byte> span, string identifier, string? teamId, HashAlgorithmName hashAlgorithm, int maxSlot, ulong codeLimit, Segment textSeg, CdFlags codeDirectoryFlags, ExecSegFlags segmentFlags, int cdSize, int idOffset, int teamIdOffset, int hashesOffset)
    {
        //The first header is the code directory header. It contains the size of the rest of the header.
        CodeDirectoryHeader header = new CodeDirectoryHeader
        {
            Magic = CsMagic.CodeDirectory,
            Length = (uint)cdSize,
            Version = UseVersion,
            Flags = codeDirectoryFlags,
            HashOffset = (uint)hashesOffset,
            IdentOffset = (uint)idOffset,
            nSpecialSlots = (uint)maxSlot,
            nCodeSlots = (uint)(((codeLimit + PageSize) - 1) / PageSize),
            CodeLimit = (uint)codeLimit, // 32bit truncated code limit
            HashSize = hashAlgorithm.GetSize(),
            HashType = GetHashType(hashAlgorithm),
            Platform = 0,
            PageSize = (byte)Math.Log2(PageSize),
            Spare2 = 0
        };

        header.Write(span);
        span = span[CodeDirectoryHeader.StructSize..];

        if (UseVersion >= Supports.SupportsScatter)
        {
            ScatterHeader scatterHeader = new ScatterHeader { ScatterOffset = 0 };
            scatterHeader.Write(span);
            span = span[ScatterHeader.StructSize..];
        }

        if (UseVersion >= Supports.SupportsTeamId)
        {
            TeamIdHeader teamIdHeader = new TeamIdHeader { TeamOffset = (uint)teamIdOffset };
            teamIdHeader.Write(span);
            span = span[TeamIdHeader.StructSize..];
        }

        if (UseVersion >= Supports.SupportsCodeLimit64)
        {
            //Note: For some reason, CodeSign sets this to 0, so I do too.
            CodeLimit64Header codeLimit64Header = new CodeLimit64Header { Spare3 = 0, CodeLimit64 = 0 }; // The full 64bit code limit
            codeLimit64Header.Write(span);
            span = span[CodeLimit64Header.StructSize..];
        }

        if (UseVersion >= Supports.SupportsExecSegment)
        {
            ExecSegmentHeader execSegmentHeader = new ExecSegmentHeader { ExecSegBase = textSeg.FileOffset, ExecSegLimit = textSeg.FileSize, ExecSegFlags = segmentFlags };
            execSegmentHeader.Write(span);
            span = span[ExecSegmentHeader.StructSize..];
        }

        //Now we have written the fixed length headers. It is time to write the variable length strings.

        //Write identifier first
        byte[] idBytes = Encoding.UTF8.GetBytes(identifier);
        idBytes.CopyTo(span);
        span = span[(idBytes.Length + 1)..]; //+1 for null byte

        //Then write the team id (if any)
        if (UseVersion >= Supports.SupportsTeamId && teamId != null)
        {
            byte[] teamIdBytes = Encoding.UTF8.GetBytes(teamId);
            teamIdBytes.CopyTo(span);
            span = span[(teamIdBytes.Length + 1)..]; //+1 for null byte
        }
    }

    private static void HashSpecialSlots(ref Span<byte> span, SortedList<CsSlot, ReadOnlyMemory<byte>> blobs, int maxSlot, IncrementalHash hasher, byte hashSize)
    {
        //Write each of the special slots hashes
        for (int i = maxSlot; i > 0; i--)
        {
            if (!blobs.ContainsKey((CsSlot)i))
            {
                //Apple make space for the missing special hashes by default
                span = span[hashSize..];
                continue;
            }

            hasher.AppendData(blobs[(CsSlot)i].Span);
            hasher.GetHashAndReset().AsSpan(0, hashSize).CopyTo(span);
            span = span[hashSize..];
        }
    }

    private static void HashCodeSlotsPatch(ref Span<byte> span, ReadOnlySpan<byte> patch, IncrementalHash hasher, int hashSize)
    {
        Debug.Assert(patch.Length % PageSize == 0, "patch must be a whole-number of pages");

        //If there is a patch, it means we are running in virtual hashing mode.
        // When true: We need to use the patch, and pad the last page to 4096
        // When false: Run on the original data only, and assume already padded to 4096

        long numPages = patch.Length / PageSize;
        for (int i = 0; i < numPages; i++)
        {
            hasher.AppendData(patch.Slice(i * PageSize, PageSize));
            hasher.GetHashAndReset().AsSpan(0, hashSize).CopyTo(span);
            span = span[hashSize..];
        }
    }

    private static void HashCodeSlots(Span<byte> span, ReadOnlySpan<byte> data, int padLen, ulong codeLimit, IncrementalHash hasher, int hashSize)
    {
        uint codeSlots = (uint)(((codeLimit + PageSize) - 1) / PageSize);
        ulong remaining = codeLimit - (ulong)padLen;
        int offset = 0;

        for (int slot = 0; slot < codeSlots - 1; ++slot)
        {
            ulong thisPage = Math.Min(remaining, PageSize);

            hasher.AppendData(data.Slice(offset, (int)thisPage));
            hasher.GetHashAndReset().AsSpan(0, hashSize).CopyTo(span);
            span = span[hashSize..];

            offset += (int)thisPage;
            remaining -= thisPage;
        }

        //Handle the last page. It is done for perf as it is the only one that has padding.
        {
            ulong thisPage = Math.Min(remaining, PageSize);
            hasher.AppendData(data.Slice(offset, (int)thisPage));

            if (padLen > 0)
                hasher.AppendData(stackalloc byte[padLen]);

            hasher.GetHashAndReset().AsSpan(0, hashSize).CopyTo(span);
        }
    }

    private static int GetCodeDirectorySize(HashAlgorithmName hashAlgorithm, string identifier, string? teamId, ulong codeLimit, int specialSlotCount, out int idOffset, out int teamIdOffset, out int hashesOffset)
    {
        //Static sizes
        int cdSize = CodeDirectoryHeader.StructSize;
        if (UseVersion >= Supports.SupportsScatter) cdSize += ScatterHeader.StructSize;
        if (UseVersion >= Supports.SupportsTeamId) cdSize += TeamIdHeader.StructSize;
        if (UseVersion >= Supports.SupportsCodeLimit64) cdSize += CodeLimit64Header.StructSize;
        if (UseVersion >= Supports.SupportsExecSegment) cdSize += ExecSegmentHeader.StructSize;

        idOffset = cdSize; //Save the offset for the team id

        //Identifier
        cdSize += Encoding.UTF8.GetByteCount(identifier) + 1; //+1 for null byte

        //TeamId
        if (UseVersion >= Supports.SupportsTeamId && !string.IsNullOrEmpty(teamId))
        {
            teamIdOffset = cdSize; //Save the offset right after the identifier
            cdSize += Encoding.UTF8.GetByteCount(teamId) + 1;
        }
        else
            teamIdOffset = 0;

        //Calculate the number of code slots. We need to round up to the next page size.
        byte hashSize = hashAlgorithm.GetSize();
        cdSize += specialSlotCount * hashSize; //Special slot hashes

        hashesOffset = cdSize; //Hashes go after the special hashes

        int codeSlotCount = (int)(((codeLimit + PageSize) - 1) / PageSize);
        cdSize += codeSlotCount * hashSize; //Code page hashes

        return cdSize;
    }

    private static byte GetHashType(HashAlgorithmName hash) => hash.Name switch
    {
        "SHA1" => 1,
        "SHA256" => 2,
        "SHA384" => 4,
        _ => throw new NotSupportedException($"Unsupported hash algorithm: {hash.Name}")
    };

    private static HashAlgorithmName GetHashAlgorithmName(byte hashType) => hashType switch
    {
        1 => HashAlgorithmName.SHA1,
        2 => HashAlgorithmName.SHA256,
        4 => HashAlgorithmName.SHA384,
        _ => throw new NotSupportedException($"Unsupported hash algorithm: {hashType}")
    };

    private static IEnumerable<X509Certificate2> GetCerts()
    {
        Assembly assembly = typeof(MachObjectFormatHandler).Assembly;

        using MemoryStream memoryStream = new MemoryStream();

        foreach (string resourceName in assembly.GetManifestResourceNames())
        {
            Debug.Assert(resourceName.StartsWith("Genbox.FastCodeSign.Internal.MachObject.Certificates.", StringComparison.OrdinalIgnoreCase));

            memoryStream.SetLength(0); //Reuse the buffer
            using (Stream? manifestStream = assembly.GetManifestResourceStream(resourceName))
                manifestStream!.CopyTo(memoryStream);

            yield return X509CertificateLoader.LoadCertificate(memoryStream.ToArray());
        }
    }

    private sealed class MachObjectInfo
    {
        public required uint SuperBlockSize { get; init; }
        public required ulong CodeLimit { get; init; }
        public required int PaddingLength { get; init; }
        public required SortedList<CsSlot, ReadOnlyMemory<byte>> Blobs { get; init; }
    }
}