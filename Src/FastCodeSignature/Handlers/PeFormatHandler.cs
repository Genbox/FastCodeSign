using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Genbox.FastCodeSignature.Abstracts;
using Genbox.FastCodeSignature.Internal;
using Genbox.FastCodeSignature.Internal.Extensions;
using Genbox.FastCodeSignature.Internal.Helpers;
using Genbox.FastCodeSignature.Internal.WinPe;
using Genbox.FastCodeSignature.Internal.WinPe.Enums;
using Genbox.FastCodeSignature.Internal.WinPe.Headers;
using Genbox.FastCodeSignature.Internal.WinPe.Spc;
using Genbox.FastCodeSignature.Models;
using static Genbox.FastCodeSignature.Internal.Helpers.ByteHelper;

namespace Genbox.FastCodeSignature.Handlers;

public sealed class PeFormatHandler : IFormatHandler
{
    // The smallest valid PE file on Windows 7+ is:
    // x86: 252 bytes
    // x64: 268 bytes
    // Source: https://www.alex-ionescu.com/pe-trick-1-a-codeless-pe-binary-file-that-runs/
    public int MinValidSize => 252;
    public string[] ValidExt => ["exe", "dll", "sys", "scr", "ocx", "cpl", "mun", "mui", "drv", "winmd", "ax", "efi"];
    public bool IsValidHeader(ReadOnlySpan<byte> data) => data[0] == 'M' && data[1] == 'Z';

    IContext IFormatHandler.GetContext(ReadOnlySpan<byte> data) => WinPeContext.Create(data);

    ReadOnlySpan<byte> IFormatHandler.ExtractSignature(IContext context, ReadOnlySpan<byte> data)
    {
        WinPeContext obj = (WinPeContext)context;

        //There is a WIN_CERTIFICATE struct here. See https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-win_certificate
        WinCertificate winCert = WinCertificate.Read(data.Slice((int)obj.SecurityVirtualAddress, (int)obj.SecuritySize));

        //See https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-win_certificate

        // We only support specific revisions and certificate types
        if ((winCert.Revision != 0x0100 && // WIN_CERT_REVISION_1_0
             winCert.Revision != 0x0200) || // WIN_CERT_REVISION_2_0
            winCert.CertificateType != 0x0002) // WIN_CERT_TYPE_PKCS_SIGNED_DATA
            return ReadOnlySpan<byte>.Empty;

        // We need to skip the 8 byte header, and subtract it from the length
        uint certDataOffset = obj.SecurityVirtualAddress + 8;
        uint certDataLength = winCert.Length - 8;

        return data.Slice((int)certDataOffset, (int)certDataLength);
    }

    byte[] IFormatHandler.ComputeHash(IContext context, ReadOnlySpan<byte> data, HashAlgorithmName hashAlgorithm)
    {
        WinPeContext obj = (WinPeContext)context;

        using IncrementalHash hasher = IncrementalHash.CreateHash(hashAlgorithm);

        int offset = 0;
        int size = (int)obj.ChecksumOffset;

        hasher.AppendData(data.Slice(offset, size));

        offset = (int)obj.ChecksumOffset + 4;
        size = (int)obj.SecurityDirOffset - offset;

        hasher.AppendData(data.Slice(offset, size));

        offset = (int)(obj.SecurityDirOffset + 8);
        size = (int)obj.SizeOfOptionalHeader - offset;

        hasher.AppendData(data.Slice(offset, size));

        uint sumOfBytesHashed = obj.SizeOfOptionalHeader;

        foreach (PeSection section in obj.Sections)
        {
            offset = (int)section.PointerToRawData;
            size = (int)section.SizeOfRawData;

            hasher.AppendData(data.Slice(offset, size));
            sumOfBytesHashed += section.SizeOfRawData;
        }

        uint remainingLength = (uint)data.Length - (obj.SecuritySize + sumOfBytesHashed);
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

    long IFormatHandler.RemoveSignature(IContext context, Span<byte> data)
    {
        WinPeContext obj = (WinPeContext)context;

        //Remove the signature by zeroing the areas where the signature resides
        ZeroSignature(data, obj);

        return (int)obj.SecuritySize;
    }

    void IFormatHandler.WriteSignature(IContext context, IAllocation allocation, Signature signature)
    {
        byte[] encodedCms = signature.SignedCms.Encode();

        //Keep a copy of the old EoF
        uint datLen = (uint)allocation.GetData().Length;
        uint dataPad = Pad(datLen, 8);
        datLen += dataPad;

        uint sigLen = (uint)encodedCms.Length;
        sigLen += Pad(sigLen, 8);

        //Create a span to contain the WIN_CERTIFICATE structure
        WinCertificate winCert = new WinCertificate
        {
            Length = WinCertificate.StructSize + sigLen,
            Revision = 0x0200, // WIN_CERT_REVISION_2_0
            CertificateType = 0x0002 // WIN_CERT_TYPE_PKCS_SIGNED_DATA
        };

        //Expand the allocation with space for our signature. Include the padding to data.
        Span<byte> ext = allocation.CreateExtension(dataPad + WinCertificate.StructSize + sigLen);
        Span<byte> span = ext[(int)dataPad..]; // Skip the padding
        winCert.Write(span);

        //Write the CMS blob after the WinCertificate header
        encodedCms.CopyTo(span[WinCertificate.StructSize..]);

        // Update the security directory entry
        WinPeContext obj = (WinPeContext)context;
        Span<byte> data = allocation.GetData();
        WriteUInt32LittleEndian(data[(int)obj.SecurityDirOffset..], datLen);
        WriteUInt32LittleEndian(data[(int)(obj.SecurityDirOffset + 4)..], WinCertificate.StructSize + sigLen);
    }

    Signature IFormatHandler.CreateSignature(IContext context, ReadOnlySpan<byte> data, X509Certificate2 cert, AsymmetricAlgorithm? privateKey, HashAlgorithmName hashAlgorithm, Action<CmsSigner>? configureSigner, bool silent)
    {
        CmsSigner signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, cert, privateKey)
        {
            DigestAlgorithm = hashAlgorithm.ToOid()
        };

        byte[] hash = ((IFormatHandler)this).ComputeHash(context, data, hashAlgorithm);

        SpcSpOpusInfo oi = new SpcSpOpusInfo(null, null);
        SpcStatementType st = new SpcStatementType([new Oid(OidConstants.MsKeyPurpose, "SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID")]);

        signer.SignedAttributes.Add(new AsnEncodedData(SpcSpOpusInfo.ObjectIdentifier, oi.Encode()));
        signer.SignedAttributes.Add(new AsnEncodedData(SpcStatementType.ObjectIdentifier, st.Encode()));

        configureSigner?.Invoke(signer);

        SpcIndirectDataContent dataContent = new SpcIndirectDataContent(
            new SpcPeImageData(SpcPeImageFlags.IncludeResources, new SpcLink(File: new SpcString(Unicode: ""))).Encode(),
            SpcPeImageData.ObjectIdentifier,
            signer.DigestAlgorithm,
            hash,
            null);

        ContentInfo contentInfo = new ContentInfo(SpcIndirectDataContent.ObjectIdentifier, dataContent.Encode());
        SignedCms signed = new SignedCms(contentInfo, false);
        signed.ComputeSignature(signer, silent);
        return new Signature(signed, null);
    }

    bool IFormatHandler.ExtractHashFromSignedCms(SignedCms signedCms, [NotNullWhen(true)]out byte[]? digest, out HashAlgorithmName algo)
    {
        SpcIndirectDataContent indirect = SpcIndirectDataContent.Decode(signedCms.ContentInfo.Content);
        digest = indirect.Digest;
        algo = OidHelper.OidToHashAlgorithm(indirect.DigestAlgorithm.Value!);
        return true;
    }

    private static void ZeroSignature(Span<byte> data, WinPeContext context)
    {
        //Zero the signature
        data.Slice((int)context.SecurityVirtualAddress, (int)context.SecuritySize).Clear();

        //NOTE: Could zero the checksum or recalculate it. However, .NET saves the compilation timestamp there, so we wouldn't get equality there anyway.

        //Zero the security directory entry (8 bytes)
        WriteInt64LittleEndian(data[(int)context.SecurityDirOffset..], 0);
    }
}