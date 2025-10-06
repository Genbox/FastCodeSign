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
using static Genbox.FastCodeSignature.Internal.Helpers.ByteHelper;

namespace Genbox.FastCodeSignature.Handlers;

public sealed class PeFormatHandler(X509Certificate2 cert, AsymmetricAlgorithm? privateKey) : IFormatHandler
{
    bool IFormatHandler.CanHandle(ReadOnlySpan<byte> data, string? ext)
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

        return true;
    }

    IContext IFormatHandler.GetContext(ReadOnlySpan<byte> data) => WinPeContext.Create(data);

    public ReadOnlySpan<byte> ExtractSignature(IContext context, ReadOnlySpan<byte> data)
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
        Span<byte> data = allocation.GetSpan();
        byte[] encodedCms = signature.SignedCms.Encode();

        //Keep a copy of the old EoF
        uint datLen = (uint)data.Length;
        datLen += Pad(datLen, 8);

        uint sigLen = (uint)encodedCms.Length;
        sigLen += Pad(sigLen, 8);

        //Set our allocation to the correct size
        allocation.SetLength(datLen + WinCertificate.StructSize + sigLen);
        data = allocation.GetSpan();

        //Create a span to contain the WIN_CERTIFICATE structure
        WinCertificate winCert = new WinCertificate
        {
            Length = WinCertificate.StructSize + sigLen,
            Revision = 0x0200, // WIN_CERT_REVISION_2_0
            CertificateType = 0x0002 // WIN_CERT_TYPE_PKCS_SIGNED_DATA
        };

        Span<byte> span = data[(int)datLen..];
        winCert.Write(span);
        encodedCms.CopyTo(span[WinCertificate.StructSize..(int)(WinCertificate.StructSize + sigLen)]);

        // Update the security directory entry
        WinPeContext obj = (WinPeContext)context;
        WriteUInt32LittleEndian(data[(int)obj.SecurityDirOffset..], datLen);
        WriteUInt32LittleEndian(data[(int)(obj.SecurityDirOffset + 4)..], WinCertificate.StructSize + sigLen);
    }

    Signature IFormatHandler.CreateSignature(IContext context, ReadOnlySpan<byte> data, HashAlgorithmName hashAlgorithm)
    {
        CmsSigner signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, cert, privateKey)
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
            signer.DigestAlgorithm, ((IFormatHandler)this).ComputeHash(context, data, OidHelper.OidToHashAlgorithm(signer.DigestAlgorithm.Value!)),
            null);

        ContentInfo contentInfo = new ContentInfo(SpcIndirectDataContent.ObjectIdentifier, dataContent.Encode());
        SignedCms signed = new SignedCms(contentInfo, false);
        signed.ComputeSignature(signer);
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