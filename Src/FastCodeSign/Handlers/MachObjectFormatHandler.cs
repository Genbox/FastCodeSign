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
using Genbox.FastCodeSign.Internal.MachObject.Requirements;
using Genbox.FastCodeSign.Models;

namespace Genbox.FastCodeSign.Handlers;

/// <summary>
/// Supports macOS Mach Object files.
/// </summary>
/// <param name="identifier">The identifier to use. By default, macOS codesign uses the filename of the file</param>
/// <param name="requirements">The requirements to use. Set to null to use macOS codesign defaults</param>
/// <param name="teamId">An optional team id. Set to null to exclude.</param>
public sealed class MachObjectFormatHandler(string identifier, RequirementSet? requirements = null, string? teamId = null) : IFormatHandler
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

        //Read the SuperBlob
        ReadOnlySpan<byte> sbSpan = data.Slice((int)obj.CodeSignature.DataOffset, (int)obj.CodeSignature.DataSize);
        SuperBlobHeader sbHeader = SuperBlobHeader.Read(sbSpan);

        if (sbHeader.Magic != CsMagic.EmbeddedSignature || sbHeader.Count == 0) //Not embedded or there are no slots in the SuperBlob
            return ReadOnlySpan<byte>.Empty;

        //Read the index structures right after the SuperBlob header
        for (int i = 0; i < sbHeader.Count; i++)
        {
            BlobIndex blobIndex = BlobIndex.Read(sbSpan[(SuperBlobHeader.StructSize + (i * BlobIndex.StructSize))..]);

            if (blobIndex.Type != CsSlot.Signature)
                continue;

            ReadOnlySpan<byte> blobSpan = sbSpan[(int)blobIndex.Offset..];
            BlobWrapper bh = BlobWrapper.Read(blobSpan);

            if (bh.Type != CsMagic.BlobWrapper) //Guard against corrupt files
                return ReadOnlySpan<byte>.Empty;

            // The CMS ASN1 is the payload of the wrapper
            return blobSpan.Slice(BlobWrapper.StructSize, (int)bh.Length - BlobWrapper.StructSize); //Length includes the header. We don't need the header.
        }

        return ReadOnlySpan<byte>.Empty; // We did not manage to find the CMS blob
    }

    byte[] IFormatHandler.ComputeHash(IContext context, ReadOnlySpan<byte> data, HashAlgorithmName hashAlgorithm)
    {
        MachOContext obj = (MachOContext)context;

        //If there is no signature, we cannot just hash the file, since Mach Object signatures require external files such as entitlement and requirements
        //We cannot require the caller to provide this data, so we simply tell them we are unable to hash unsigned files. That's what macOS's CodeSign does also.
        if (!obj.IsSigned)
            throw new InvalidOperationException("Mach Object does not support stable hashing");

        //Read the SuperBlob. We need to read the CodeDirectory header & hash the special slots.
        ReadOnlySpan<byte> sbSpan = data.Slice((int)obj.CodeSignature.DataOffset, (int)obj.CodeSignature.DataSize);
        SuperBlobHeader sbHeader = SuperBlobHeader.Read(sbSpan);

        if (sbHeader.Magic != CsMagic.EmbeddedSignature || sbHeader.Count == 0)
            throw new InvalidOperationException("The signature is not embedded in the file");

        //Locate the CodeDirectory blob inside the SuperBlob.
        ReadOnlySpan<byte> cdSpan = ReadOnlySpan<byte>.Empty;

        //We need to store the blob indexes we see to later lookup in the array to find special slots
        List<BlobIndex> slots = new List<BlobIndex>();

        for (int i = 0; i < sbHeader.Count; i++)
        {
            BlobIndex blobIdx = BlobIndex.Read(sbSpan[(SuperBlobHeader.StructSize + (i * BlobWrapper.StructSize))..]);
            slots.Add(blobIdx);

            if (blobIdx.Type != CsSlot.CodeDirectory)
                continue;

            ReadOnlySpan<byte> blobSpan = sbSpan[(int)blobIdx.Offset..];
            BlobWrapper blobHeader = BlobWrapper.Read(blobSpan);

            if (blobHeader.Type != CsMagic.CodeDirectory)
                throw new InvalidOperationException("Unexpected CodeDirectory magic");

            cdSpan = blobSpan[..(int)blobHeader.Length];
        }

        if (cdSpan.IsEmpty)
            throw new InvalidOperationException("Unable to find a CodeDirectory blob in the signature");

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

        //We create two hashers here. One to produce special/code page hashes, and one to consume the hashes which eventually become the CodeDirectory hash.
        HashAlgorithmName hashName = GetHashAlgorithmName(hashType);
        using IncrementalHash hasher = IncrementalHash.CreateHash(hashName);
        using IncrementalHash cdHasher = IncrementalHash.CreateHash(hashName);

        //We take the CodeDirectory header (without the hashes) and hash it. The header includes the static header + the dynamic headers (version specific) + the header data (identity and teamid)
        //We assume we can read from offset 0 to the offset where special hashes begin.
        cdHasher.AppendData(cdSpan[..(int)(hashOff - (nSpecial * hashSize))]); //Go from hash offset, then backwards the number of special hashes

        ReadOnlySpan<byte> emptyHash = stackalloc byte[hashSize];

        //Then we go through the blobs, find special slots, and hash the content, then add the hash to cdHasher
        for (int i = (int)nSpecial; i > 0; i--)
        {
            ReadOnlySpan<byte> blobSpan = ReadOnlySpan<byte>.Empty;

            foreach (BlobIndex blobIndex in slots)
            {
                if (blobIndex.Type != (CsSlot)i)
                    continue;

                blobSpan = sbSpan[(int)blobIndex.Offset..];
                break;
            }

            if (blobSpan.IsEmpty)
                cdHasher.AppendData(emptyHash);
            else
            {
                BlobWrapper blobHeader = BlobWrapper.Read(blobSpan);
                hasher.AppendData(blobSpan[..(int)blobHeader.Length]);
                cdHasher.AppendData(hasher.GetHashAndReset().AsSpan(0, hashSize));
            }
        }

        //Now we need to hash the file in <pageSize> chunks up to <codeLimit> and add the hashes to cdHasher
        uint pageSize = (uint)(1 << pageSizeLg2);

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

        //Remove the LC_CODE_SIGNATURE command from the list of load commands. It is the last command in the list.
        const uint size = LoadCommandHeader.StructSize + CodeSignatureHeader.StructSize;

        //Clear the LC header and the LC_CODE_SIGNATURE command entry
        data.Slice(obj.CodeSignature.Offset - LoadCommandHeader.StructSize, (int)size).Clear();

        //Update Mach Object header
        bool le = obj.IsLittleEndian;
        WriteU32(data, 16, obj.MachHeader.NumberOfCommands - 1, le);
        WriteU32(data, 20, obj.MachHeader.SizeOfCommands - size, le);

        //Note: This leaves a 16-byte gap at the end of the load commands, but that's fine.

        //Shrink __LINKEDIT.filesize
        ulong newFileSize = obj.LinkEdit.FileSize - obj.CodeSignature.DataSize;

        int headerSize = obj.Is64Bit ? 32 : 28;

        if (obj.Is64Bit)
        {
            WriteU64(data, obj.LinkEdit.Offset + headerSize + 0, Align(newFileSize, 16384), le);
            WriteU64(data, obj.LinkEdit.Offset + headerSize + 16, newFileSize, le);
        }
        else
        {
            WriteU32(data, obj.LinkEdit.Offset + headerSize + 0, (uint)Align(newFileSize, 16384), le);
            WriteU32(data, obj.LinkEdit.Offset + headerSize + 8, (uint)newFileSize, le);
        }

        ulong leEnd = obj.LinkEdit.FileOffset + obj.LinkEdit.FileSize; //End of __LINKEDIT
        ulong csEnd = obj.CodeSignature.DataOffset + obj.CodeSignature.DataSize; //End of the code signature

        Debug.Assert(csEnd == leEnd, "The code directory end must match the link edit end");
        Debug.Assert((ulong)data.Length == leEnd, "The link edit section must end at the end of the file");

        return obj.CodeSignature.DataSize;
    }

    void IFormatHandler.WriteSignature(IContext context, IAllocation allocation, Signature signature)
    {
        MachOContext obj = (MachOContext)context;

        Span<byte> data = allocation.GetSpan();
        int oldSize = data.Length;
        MachObjectInfo info = (MachObjectInfo)signature.SignatureInfo!;

        ulong codeLimit = info.CodeLimit;
        int padLen = info.PaddingLength;
        uint sbSize = info.SuperBlockSize;

        SortedList<CsSlot, byte[]> blobs = new SortedList<CsSlot, byte[]>(info.Blobs); //We copy the collection to avoid duplicating the signature blob on multiple calls to WriteSignature
        blobs.Add(CsSlot.Signature, signature.SignedCms.Encode());

        //We need to update the header etc. before adding the CodeDirectory as it calculates page hashes, and they otherwise won't be correct.
        WriteHeaders(data, obj, codeLimit, padLen, sbSize);

        allocation.SetLength((uint)(oldSize + padLen + sbSize)); //Extend the allocation with the SuperBlob
        data = allocation.GetSpan();

        //Set the span at after the file where the SB begins
        data = data[(oldSize + padLen)..];

        // Write the SuperBlob header
        WriteUInt32BigEndian(data[..], (uint)CsMagic.EmbeddedSignature);
        WriteUInt32BigEndian(data[4..], (uint)(SuperBlobHeader.StructSize + blobs.Sum(x => x.Value.Length + BlobIndex.StructSize) + BlobWrapper.StructSize)); //The BlobWrapper is for the CMS blob
        WriteUInt32BigEndian(data[8..], (uint)blobs.Count);
        data = data[SuperBlobHeader.StructSize..];

        //Write all the SuperBlob payload headers
        int dataOffset = SuperBlobHeader.StructSize + (blobs.Count * BlobIndex.StructSize);
        foreach (KeyValuePair<CsSlot, byte[]> blob in blobs)
        {
            //Write a blob index
            WriteUInt32BigEndian(data, (uint)blob.Key);
            WriteUInt32BigEndian(data[4..], (uint)dataOffset);
            data = data[8..];
            dataOffset += blob.Value.Length;
        }

        //Write the payloads
        foreach (KeyValuePair<CsSlot, byte[]> blob in blobs)
        {
            // Wrap CMS in a blob wrapper. We do it here to avoid creating a buffer after encoding the CMS just to add a wrapper to the byte-array
            if (blob.Key == CsSlot.Signature)
            {
                WriteUInt32BigEndian(data, (uint)CsMagic.BlobWrapper);
                WriteUInt32BigEndian(data[4..], (uint)blob.Value.Length + 8);
                data = data[8..];
            }

            //Write the actual blob
            blob.Value.CopyTo(data);
            data = data[blob.Value.Length..];
        }
    }

    Signature IFormatHandler.CreateSignature(IContext context, ReadOnlySpan<byte> data, X509Certificate2 cert, AsymmetricAlgorithm? privateKey, HashAlgorithmName hashAlgorithm, Action<CmsSigner>? configureSigner, bool silent)
    {
        if (identifier == null!)
            throw new ArgumentNullException(nameof(identifier), $"Identifier cannot be null. Please supply a filename or set the identifier directly on {nameof(MachObjectFormatHandler)}");

        CmsSigner signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, cert, privateKey)
        {
            DigestAlgorithm = hashAlgorithm.ToOid(),
            IncludeOption = X509IncludeOption.None
        };

        //Build the SuperBlob
        SortedList<CsSlot, byte[]> blobs = new SortedList<CsSlot, byte[]>();

        RequirementSet? req = requirements;

        if (req == null)
            if (cert.IsAppleDeveloperCertificate())
                req = RequirementSet.CreateAppleDevDefault(identifier, cert);
            else
                req = RequirementSet.CreateDefault(identifier, cert);

        blobs.Add(CsSlot.Requirements, req.ToArray());

        int maxSlot = blobs.Count == 0 ? 0 : blobs.Max(x => (int)x.Key); // We need to extract this here for max special slot

        MachOContext obj = (MachOContext)context;
        ulong linkEditEnd = obj.LinkEdit.FileOffset + obj.LinkEdit.FileSize;
        Debug.Assert((uint)linkEditEnd == data.Length);

        ulong codeLimit = Align(linkEditEnd, 16); // Start of SuperBlob (16 byte aligned)
        int cdSize = GetCodeDirectorySize(hashAlgorithm, codeLimit, maxSlot, out int idOffset, out int teamIdOffset, out int hashesOffset);

        byte[] cdBlob = new byte[cdSize];
        blobs.Add(CsSlot.CodeDirectory, cdBlob);

        Span<byte> cdSpan = cdBlob.AsSpan();
        WriteCodeDirectoryHeader(ref cdSpan, hashAlgorithm, maxSlot, codeLimit, obj.Text, ExecSegFlags.MainBinary, cdSize, idOffset, teamIdOffset, hashesOffset);

        uint sbSize = Align((uint)(SuperBlobHeader.StructSize // SuperBlob header size
                                   + BlobWrapper.StructSize + CmsSizeEst //CMS wrapper header size + estimated cms size
                                   + blobs.Sum(x => x.Value.Length + BlobIndex.StructSize)), 16); //Size of all the blobs

        //We need to update the header etc. before adding the CodeDirectory as it calculates page hashes, and they otherwise won't be correct.
        //Create a temporary storage for patching the header (paged aligned to make things easier down the road)

        //The length is headerSize + sizeOfCommands + loadCommandHeaderSize + codeSignatureHeaderSize
        byte[] patch = new byte[Align((uint)((obj.Is64Bit ? 32 : 28) + obj.MachHeader.SizeOfCommands + LoadCommandHeader.StructSize + CodeSignatureHeader.StructSize), PageSize)];
        data[..patch.Length].CopyTo(patch);
        data = data[patch.Length..]; //Advance data by the page size

        int padLen = checked((int)(codeLimit - linkEditEnd));
        WriteHeaders(patch, obj, codeLimit, padLen, sbSize);

        byte[] cdHash;
        using (IncrementalHash hasher = IncrementalHash.CreateHash(hashAlgorithm))
        {
            byte hashSize = hashAlgorithm.GetSize();

            HashSpecialSlots(ref cdSpan, blobs, maxSlot, hasher, hashSize);
            HashCodeSlotsPatch(ref cdSpan, patch, hasher, hashSize);
            HashCodeSlots(cdSpan, data, padLen, codeLimit - (ulong)patch.Length, hasher, hashSize);

            hasher.AppendData(cdBlob);
            cdHash = hasher.GetHashAndReset();
        }

        using X509Chain chain = new X509Chain();
        X509ChainPolicy chainPolicy = new X509ChainPolicy { TrustMode = X509ChainTrustMode.CustomRootTrust };
        chainPolicy.CustomTrustStore.Add(cert); //We add itself because it might be self-signed

        foreach (X509Certificate2 appleCert in GetCerts())
            chainPolicy.CustomTrustStore.Add(appleCert);

        chain.ChainPolicy = chainPolicy;

        if (!chain.Build(cert) && !Array.TrueForAll(chain.ChainStatus, s => s.Status is X509ChainStatusFlags.InvalidExtension or X509ChainStatusFlags.HasNotSupportedCriticalExtension))
            throw new InvalidOperationException("Unable to build certificate chain");

        signer.Certificates.AddRange(chain.ChainElements.Select(x => x.Certificate).ToArray());
        signer.SignedAttributes.Add(new Pkcs9SigningTime());

        signer.SignedAttributes.Add(MakeAttribute(OidConstants.AppleHashAttrOid,
            EncodeSeq(hashAlgorithm.ToOidString(), cdHash)));

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
        signed.ComputeSignature(signer, silent);

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

    private static void WriteHeaders(Span<byte> span, MachOContext obj, ulong codeLimit, int padLength, uint sbSize)
    {
        bool le = obj.IsLittleEndian;

        // Bump counts in the mach object header
        WriteU32(span, 16, obj.MachHeader.NumberOfCommands + 1, le);
        WriteU32(span, 20, obj.MachHeader.SizeOfCommands + LoadCommandHeader.StructSize + CodeSignatureHeader.StructSize, le);

        // We need to insert the new load command right after the header
        int headerSize = obj.Is64Bit ? 32 : 28;
        int headerEnd = headerSize + (int)obj.MachHeader.SizeOfCommands;

        //Write CodeSignature
        WriteU32(span, headerEnd + 0, (uint)LoadCommandType.CODE_SIGNATURE, le);
        WriteU32(span, headerEnd + 4, LoadCommandHeader.StructSize + CodeSignatureHeader.StructSize, le);
        WriteU32(span, headerEnd + 8, (uint)codeLimit, le); //Offset
        WriteU32(span, headerEnd + 12, sbSize, le); //Length

        //Update LinkEdit header with new size
        ulong newLinkEditSize = obj.LinkEdit.FileSize + (uint)padLength + sbSize;

        if (obj.Is64Bit)
        {
            WriteU64(span, headerSize + obj.LinkEdit.Offset + 0, Align(newLinkEditSize, 16384), le); // vmsize
            WriteU64(span, headerSize + obj.LinkEdit.Offset + 16, newLinkEditSize, le); // filesize
        }
        else
        {
            WriteU32(span, headerSize + obj.LinkEdit.Offset + 0, checked((uint)Align(newLinkEditSize, 16384)), le); // vmsize
            WriteU32(span, headerSize + obj.LinkEdit.Offset + 8, checked((uint)newLinkEditSize), le); // filesize
        }
    }

    private void WriteCodeDirectoryHeader(ref Span<byte> span, HashAlgorithmName hashAlgorithm, int maxSlot, ulong codeLimit, Segment textSeg, ExecSegFlags segmentFlags, int cdSize, int idOffset, int teamIdOffset, int hashesOffset)
    {
        //The first header is the code directory header. It contains the size of the rest of the header.
        CodeDirectoryHeader header = new CodeDirectoryHeader
        {
            Magic = CsMagic.CodeDirectory,
            Length = (uint)cdSize,
            Version = UseVersion,
            Flags = CdFlags.None,
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

    private static void HashSpecialSlots(ref Span<byte> span, SortedList<CsSlot, byte[]> blobs, int maxSlot, IncrementalHash hasher, byte hashSize)
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

            hasher.AppendData(blobs[(CsSlot)i]);
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

    private int GetCodeDirectorySize(HashAlgorithmName hashAlgorithm, ulong codeLimit, int specialSlotCount, out int idOffset, out int teamIdOffset, out int hashesOffset)
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

    private static void WriteU32(Span<byte> span, int offset, uint value, bool le)
    {
        if (le)
            WriteUInt32LittleEndian(span.Slice(offset, 4), value);
        else
            WriteUInt32BigEndian(span.Slice(offset, 4), value);
    }

    private static void WriteU64(Span<byte> span, int offset, ulong value, bool le)
    {
        if (le)
            WriteUInt64LittleEndian(span.Slice(offset, 8), value);
        else
            WriteUInt64BigEndian(span.Slice(offset, 8), value);
    }

    private static IEnumerable<X509Certificate2> GetCerts()
    {
        Assembly assembly = typeof(MachObjectFormatHandler).Assembly;

        using MemoryStream memoryStream = new MemoryStream();

        foreach (string resourceName in assembly.GetManifestResourceNames())
        {
            if (!resourceName.StartsWith("Genbox.FastCodeSign.Internal.MachObject.Certificates.", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Loading different file than expected");

            using (Stream? manifestStream = assembly.GetManifestResourceStream(resourceName))
                manifestStream!.CopyTo(memoryStream);

            yield return X509CertificateLoader.LoadCertificate(memoryStream.ToArray());

            memoryStream.Position = 0; //To reuse the stream
        }
    }

    private sealed class MachObjectInfo
    {
        public required uint SuperBlockSize { get; init; }
        public required ulong CodeLimit { get; init; }
        public required int PaddingLength { get; init; }
        public required SortedList<CsSlot, byte[]> Blobs { get; init; }
    }
}