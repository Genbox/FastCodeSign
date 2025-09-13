using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Genbox.FastCodeSignature.Abstracts;
using Genbox.FastCodeSignature.Internal;
using Genbox.FastCodeSignature.Internal.Extensions;
using Genbox.FastCodeSignature.Internal.Helpers;
using Genbox.FastCodeSignature.Internal.WinPe.Enums;
using Genbox.FastCodeSignature.Internal.WinPe.Headers;
using Genbox.FastCodeSignature.Internal.WinPe.Spc;
using static Genbox.FastCodeSignature.Internal.Helpers.ByteHelper;

namespace Genbox.FastCodeSignature.Handlers;

public sealed class PeFormatHandler(X509Certificate2 cert) : IFormatHandler
{
    public bool IsValid(ReadOnlySpan<byte> data, string? ext)
    {
        // The smallest valid PE file on Windows 7+ is:
        // x86: 252 bytes
        // x64: 268 bytes
        // Source: https://www.alex-ionescu.com/pe-trick-1-a-codeless-pe-binary-file-that-runs/
        if (data.Length < 252)
            return false;

        if (ext != null
            && ext != "exe"
            && ext != "dll"
            && ext != "sys"
            && ext != "scr"
            && ext != "ocx"
            && ext != "cpl"
            && ext != "mun"
            && ext != "mui"
            && ext != "drv"
            && ext != "winmd"
            && ext != "ax"
            && ext != "efi")
            return false;

        ushort dosSignature = ReadUInt16LittleEndian(data);

        if (dosSignature != 0x5A4D) //MZ
            return false;

        // DOS header: Read e_lfanew, which is the pointer to the COFF header
        uint coffHeaderOffset = ReadUInt32LittleEndian(data[60..]);

        // COFF header: Read the PE signature
        uint peSignature = ReadUInt32LittleEndian(data[(int)coffHeaderOffset..]);
        return peSignature == 0x00004550; // "PE\0\0"
    }

    public ReadOnlySpan<byte> ExtractSignature(ReadOnlySpan<byte> data)
    {
        PeFileContext context = GetContext(data);

        // There is no signature
        if (!IsSigned(context))
            return ReadOnlySpan<byte>.Empty;

        //There is a WIN_CERTIFICATE struct here. See https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-win_certificate
        WinCertificate winCert = WinCertificate.Read(data.Slice((int)context.SecurityVirtualAddress, (int)context.SecuritySize));

        //See https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-win_certificate

        // We only support specific revisions and certificate types
        if ((winCert.Revision != 0x0100 && // WIN_CERT_REVISION_1_0
             winCert.Revision != 0x0200) || // WIN_CERT_REVISION_2_0
            winCert.CertificateType != 0x0002) // WIN_CERT_TYPE_PKCS_SIGNED_DATA
            return ReadOnlySpan<byte>.Empty;

        // We need to skip the 8 byte header, and subtract it from the length
        uint certDataOffset = context.SecurityVirtualAddress + 8;
        uint certDataLength = winCert.Length - 8;

        return data.Slice((int)certDataOffset, (int)certDataLength);
    }

    public byte[] ComputeHash(ReadOnlySpan<byte> data, HashAlgorithmName hashAlgorithm)
    {
        PeFileContext context = GetContext(data);

        using IncrementalHash hasher = IncrementalHash.CreateHash(hashAlgorithm);

        int offset = 0;
        int size = (int)context.ChecksumOffset;

        hasher.AppendData(data.Slice(offset, size));

        offset = (int)context.ChecksumOffset + 4;
        size = (int)context.SecurityDirOffset - offset;

        hasher.AppendData(data.Slice(offset, size));

        offset = (int)(context.SecurityDirOffset + 8);
        size = (int)context.SizeOfOptionalHeader - offset;

        hasher.AppendData(data.Slice(offset, size));

        uint sumOfBytesHashed = context.SizeOfOptionalHeader;

        foreach (PeSection section in context.Sections)
        {
            offset = (int)section.PointerToRawData;
            size = (int)section.SizeOfRawData;

            hasher.AppendData(data.Slice(offset, size));
            sumOfBytesHashed += section.SizeOfRawData;
        }

        uint remainingLength = (uint)data.Length - (context.SecuritySize + sumOfBytesHashed);
        if (remainingLength > 0)
        {
            offset = (int)sumOfBytesHashed;
            size = (int)remainingLength;

            hasher.AppendData(data.Slice(offset, size));
        }

        uint pad = Pad(sumOfBytesHashed + remainingLength, 8);

        if (pad > 0)
            hasher.AppendData(stackalloc byte[(int)pad]);

        return hasher.GetHashAndReset();
    }

    public long RemoveSignature(Span<byte> data)
    {
        PeFileContext context = GetContext(data);

        //The file is not signed. Do nothing.
        if (!IsSigned(context))
            return 0;

        //Remove the signature by zeroing the areas where the signature resides
        ZeroSignature(data, context);

        //Left-shifting any trailing data that could be after the signature
        return LeftShiftData(data, context.SecurityVirtualAddress, context.SecuritySize);
    }

    public void WriteSignature(IAllocation allocation, Signature signature)
    {
        Span<byte> data = allocation.GetSpan();
        PeFileContext context = GetContext(data);

        uint extraSize;

        byte[] encodedCms = signature.SignedCms.Encode();

        if (IsSigned(context))
        {
            ZeroSignature(data, context);

            //If there already is space for the new signature, reuse it.
            //Truncate/extend the buffer to exactly the size we need.

            int delta = encodedCms.Length - (int)context.SecuritySize;

            // If delta is 0, there is exactly the space we need.

            if (delta > 0) // There is more space than needed. Truncate the buffer.
                extraSize = LeftShiftData(data, context.SecurityVirtualAddress, (uint)delta);
            else if (delta < 0) // There is less space than needed. Extend the buffer.
                extraSize = RightShiftData(data, context.SecuritySize, (uint)-delta);
            else
                extraSize = 0;
        }
        else
            extraSize = 8; //8 = WIN_CERTIFICATE header

        //Keep a copy of the old EoF
        uint datLen = (uint)data.Length;
        datLen += Pad(datLen, 8);

        uint sigLen = (uint)encodedCms.Length;
        sigLen += Pad(sigLen, 8);

        //Set our allocation to the correct size
        allocation.SetLength(datLen + sigLen + extraSize);
        data = allocation.GetSpan();

        //Create a span to contain the WIN_CERTIFICATE structure
        WinCertificate winCert = new WinCertificate
        {
            Length = sigLen + 8,
            Revision = 0x0200, // WIN_CERT_REVISION_2_0
            CertificateType = 0x0002 // WIN_CERT_TYPE_PKCS_SIGNED_DATA
        };

        Span<byte> span = data[(int)datLen..];
        winCert.Write(span);
        encodedCms.CopyTo(span[WinCertificate.StructSize..]); // bCertificate

        // Update the security directory entry
        WriteUInt32LittleEndian(data[(int)context.SecurityDirOffset..], datLen);
        WriteUInt32LittleEndian(data[(int)(context.SecurityDirOffset + 4)..], sigLen + 8); //8 = WIN_CERTIFICATE header
    }

    public Signature CreateSignature(ReadOnlySpan<byte> data, HashAlgorithmName hashAlgorithm)
    {
        CmsSigner signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, cert)
        {
            DigestAlgorithm = hashAlgorithm.ToOid()
        };

        SpcSpOpusInfo oi = new SpcSpOpusInfo(new SpcString(Unicode: ""), new SpcLink(Url: ""));
        SpcStatementType st = new SpcStatementType([new Oid(OidConstants.MsKeyPurpose, "SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID")]);

        AsnEncodedData[] attributesToSign =
        [
            new AsnEncodedData(SpcSpOpusInfo.ObjectIdentifier, oi.Encode()),
            new AsnEncodedData(SpcStatementType.ObjectIdentifier, st.Encode())
        ];

        foreach (AsnEncodedData toSign in attributesToSign)
            signer.SignedAttributes.Add(toSign);

        SpcIndirectDataContent dataContent = new SpcIndirectDataContent(
            new SpcPeImageData(SpcPeImageFlags.IncludeResources, new SpcLink(File: new SpcString(Unicode: ""))).Encode(),
            SpcPeImageData.ObjectIdentifier,
            signer.DigestAlgorithm,
            ComputeHash(data, OidHelper.OidToHashAlgorithm(signer.DigestAlgorithm.Value!)),
            null);

        ContentInfo contentInfo = new ContentInfo(SpcIndirectDataContent.ObjectIdentifier, dataContent.Encode());
        SignedCms signed = new SignedCms(contentInfo, false);
        signed.ComputeSignature(signer);
        return new Signature(signed, null);
    }

    public bool TryGetHash(SignedCms signedCms, [NotNullWhen(true)]out byte[]? digest, out HashAlgorithmName algo)
    {
        SpcIndirectDataContent indirect = SpcIndirectDataContent.Decode(signedCms.ContentInfo.Content);
        digest = indirect.Digest;
        algo = OidHelper.OidToHashAlgorithm(indirect.DigestAlgorithm.Value!);
        return true;
    }

    private static void ZeroSignature(Span<byte> data, PeFileContext context)
    {
        //Zero the signature
        data.Slice((int)context.SecurityVirtualAddress, (int)context.SecuritySize).Clear();

        //Zero the security directory entry (8 bytes)
        WriteInt64LittleEndian(data[(int)context.SecurityDirOffset..], 0);
    }

    private static PeFileContext GetContext(ReadOnlySpan<byte> data)
    {
        // Docs: https://upload.wikimedia.org/wikipedia/commons/1/1b/Portable_Executable_32_bit_Structure_in_SVG_fixed.svg

        // DOS header: Read e_lfanew, which is the pointer to the COFF header
        uint coffHeaderOffset = ReadUInt32LittleEndian(data[60..]);
        ushort numberOfSections = ReadUInt16LittleEndian(data[(int)(coffHeaderOffset + 6)..]);
        ushort sizeOfOptionalHeader = ReadUInt16LittleEndian(data[(int)(coffHeaderOffset + 20)..]);
        uint optionalHeaderOffset = coffHeaderOffset + 24;
        ushort magic = ReadUInt16LittleEndian(data[(int)optionalHeaderOffset..]);

        uint sectionTableOffset = optionalHeaderOffset + sizeOfOptionalHeader;

        // Read PE sections
        List<PeSection> sections = new List<PeSection>(numberOfSections);

        for (uint i = 0; i < numberOfSections; i++)
        {
            uint sh = sectionTableOffset + (i * 40); //40 = section header size

            uint sizeOfRawData = ReadUInt32LittleEndian(data[((int)sh + 16)..]);
            uint pointerToRawData = ReadUInt32LittleEndian(data[((int)sh + 20)..]);

            if (sizeOfRawData > 0)
                sections.Add(new PeSection(sizeOfRawData, pointerToRawData));
        }

        uint sizeOfHeaders = ReadUInt32LittleEndian(data[((int)optionalHeaderOffset + 60)..]);

        // Skip 4-byte checksum, then hash to before security directory
        uint checksumOffset = coffHeaderOffset + 88;

        // Magic values:
        // - 0x10b: 32bit
        // - 0x20b: 64bit
        // Find the offset to the security data directory (contains the authenticode certificates)
        uint dataDirOffset = (uint)(coffHeaderOffset + (magic == 0x10b ? 120 : 136));

        // Data Directory is a set of (PVA + Size) which is 8 bytes in total.
        uint securityDirOffset = dataDirOffset + (4 * 8); // entry #4
        uint securityVirtualAddress = ReadUInt32LittleEndian(data[(int)securityDirOffset..]);
        uint securitySize = ReadUInt32LittleEndian(data[(int)(securityDirOffset + 4)..]);

        return new PeFileContext
        {
            ChecksumOffset = checksumOffset,
            SizeOfOptionalHeader = sizeOfHeaders,
            Sections = sections.OrderBy(h => h.PointerToRawData).ToArray(),
            SecurityDirOffset = securityDirOffset,
            SecurityVirtualAddress = securityVirtualAddress,
            SecuritySize = securitySize
        };
    }

    private static bool IsSigned(in PeFileContext context) => context.SecurityDirOffset != 0 && context.SecurityVirtualAddress != 0 && context.SecuritySize > 12;

    [StructLayout(LayoutKind.Auto)]
    private readonly ref struct PeFileContext
    {
        internal uint ChecksumOffset { get; init; }
        internal uint SizeOfOptionalHeader { get; init; }
        internal PeSection[] Sections { get; init; }
        internal uint SecurityDirOffset { get; init; }
        internal uint SecurityVirtualAddress { get; init; }
        internal uint SecuritySize { get; init; }
    }

    [StructLayout(LayoutKind.Auto)]
    private readonly record struct PeSection(uint SizeOfRawData, uint PointerToRawData);
}