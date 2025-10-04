using System.Buffers;
using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Genbox.FastCodeSignature.Abstracts;
using Genbox.FastCodeSignature.Internal.Extensions;
using Genbox.FastCodeSignature.Internal.Helpers;
using Genbox.FastCodeSignature.Internal.TextFile;
using Genbox.FastCodeSignature.Internal.WinPe.Spc;

namespace Genbox.FastCodeSignature.Handlers;

public abstract class TextFormatHandler(X509Certificate2 cert, AsymmetricAlgorithm? privateKey, string commentStart, string commentEnd, Encoding fallbackEncoding, string extension) : IFormatHandler
{
    public bool CanHandle(ReadOnlySpan<byte> data, string? ext)
    {
        if (ext == null)
            return true;

        return ext == extension;
    }

    public IContext GetContext(ReadOnlySpan<byte> data) => TextContext.Create(data, commentStart, commentEnd, fallbackEncoding);

    public ReadOnlySpan<byte> ExtractSignature(IContext context, ReadOnlySpan<byte> data)
    {
        TextContext obj = (TextContext)context;

        //Get the base64 content of the signature (includes comments)
        ReadOnlySpan<byte> span = data[(obj.HeaderIdx + obj.HeaderSig.Length)..(obj.FooterIdx - obj.FooterSig.Length)];

        //The signature is always within the ASCII range, so if we have a UTF-16 encoding, let's convert the span to UTF-8.
        if (obj.Encoding.Equals(Encoding.Unicode))
        {
            //There is no byte -> byte conversion in .NET, so we need to do it ourselves.
            Span<byte> utf8Buffer = new byte[span.Length / 2];

            // UTF-16LE: [ascii, 0x00] per char.
            int offset = 0;
            for (int i = 0; i < span.Length; i += 2)
                utf8Buffer[offset++] = span[i];

            span = utf8Buffer;
        }

        return DecodeUtf8Base64(span);
    }

    public byte[] ComputeHash(IContext context, ReadOnlySpan<byte> data, HashAlgorithmName hashAlgorithm)
    {
        TextContext obj = (TextContext)context;

        //If the data is signed, we omit the signature
        if (context.IsSigned)
            data = data[..obj.HeaderIdx];

        //If the input data is UTF8, we need to convert it to UTF16.
        if (obj.Encoding.Equals(Encoding.UTF8))
            data = Encoding.Unicode.GetBytes(Encoding.UTF8.GetString(data)); //TODO: This is not the most efficient way to do this.

        using IncrementalHash hasher = IncrementalHash.CreateHash(hashAlgorithm);
        hasher.AppendData(data);
        return hasher.GetHashAndReset();
    }

    public long RemoveSignature(IContext context, Span<byte> data)
    {
        TextContext obj = (TextContext)context;
        return obj.FooterIdx - obj.HeaderIdx;
    }

    public void WriteSignature(IContext context, IAllocation allocation, Signature signature)
    {
        Span<byte> data = allocation.GetSpan();

        TextContext obj = (TextContext)context;
        Span<byte> startComment = obj.Encoding.GetBytes(commentStart);
        Span<byte> endComment = obj.Encoding.GetBytes(commentEnd);
        Span<byte> newLine = obj.Encoding.GetBytes(TextContext.NewLine);

        byte[] encoded = signature.SignedCms.Encode();

        int base64Length = Base64.GetMaxEncodedToUtf8Length(encoded.Length);

        Span<byte> base64 = base64Length < 2048 ? stackalloc byte[base64Length] : new byte[base64Length];

        if (Base64.EncodeToUtf8(encoded, base64, out _, out int written) != OperationStatus.Done)
            throw new InvalidOperationException("Failed to encode signature");

        //In case the buffer was larger than needed
        base64 = base64[..written];

        if (obj.Encoding.Equals(Encoding.Unicode))
            base64 = obj.Encoding.GetBytes(Encoding.UTF8.GetString(base64)); //TODO: This is not the most efficient way to do this.

        int idx;

        if (obj.HeaderIdx == -1 || obj.FooterIdx == -1) // Not signed
            idx = data.Length;
        else
            idx = obj.HeaderIdx;

        int headersLen = obj.HeaderSig.Length + obj.FooterSig.Length; // Space for header/footer (already includes comments and newlines)
        int commentLen = ((commentStart.Length + commentEnd.Length + newLine.Length) * (((base64Length + 64) - 1) / 64)) - newLine.Length; // space for comments

        allocation.SetLength((uint)(idx + headersLen + commentLen + base64.Length));

        //Get a new span with the updated length
        data = allocation.GetSpan();

        //Write the header (includes comment)
        obj.HeaderSig.CopyTo(data[idx..]);
        idx += obj.HeaderSig.Length;

        int base64Rem = base64.Length;
        int base64Offset = 0;

        while (base64Rem > 0)
        {
            // Write start comment
            startComment.CopyTo(data[idx..]);
            idx += startComment.Length;

            // Take up to 64 bytes of base64 and write to span
            int toWrite = Math.Min(base64Rem, 64);
            ReadOnlySpan<byte> segment = base64.Slice(base64Offset, toWrite);
            segment.CopyTo(data[idx..]);
            idx += toWrite;

            if (commentEnd.Length > 0)
            {
                // Write end comment
                endComment.CopyTo(data[idx..]);
                idx += endComment.Length;
            }

            base64Rem -= toWrite;
            base64Offset += toWrite;

            if (base64Rem > 0)
            {
                //Write newline
                newLine.CopyTo(data[idx..]);
                idx += newLine.Length;
            }
        }

        // Write footer
        obj.FooterSig.CopyTo(data[idx..]);
    }

    public bool ExtractHashFromSignedCms(SignedCms signedCms, [NotNullWhen(true)]out byte[]? digest, out HashAlgorithmName algo)
    {
        SpcIndirectDataContent indirect = SpcIndirectDataContent.Decode(signedCms.ContentInfo.Content);
        digest = indirect.Digest;
        algo = OidHelper.OidToHashAlgorithm(indirect.DigestAlgorithm.Value!);
        return true;
    }

    public Signature CreateSignature(IContext context, ReadOnlySpan<byte> data, HashAlgorithmName hashAlgorithm)
    {
        CmsSigner signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, cert, privateKey)
        {
            DigestAlgorithm = hashAlgorithm.ToOid()
        };

        byte[] hash = ComputeHash(context, data, hashAlgorithm);

        SpcSpOpusInfo oi = new SpcSpOpusInfo(null, null);
        SpcStatementType st = new SpcStatementType([new Oid("1.3.6.1.4.1.311.2.1.21", "SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID")]);

        AsnEncodedData[] attrs =
        [
            new AsnEncodedData(SpcSpOpusInfo.ObjectIdentifier, oi.Encode()),
            new AsnEncodedData(SpcStatementType.ObjectIdentifier, st.Encode())
        ];

        foreach (AsnEncodedData attr in attrs)
            signer.SignedAttributes.Add(attr);

        SpcIndirectDataContent dataContent = new SpcIndirectDataContent(
            new SpcSipInfo(65536, SpcSipInfo.SecurityProviderGuid).Encode(),
            SpcSipInfo.ObjectIdentifier,
            signer.DigestAlgorithm,
            hash,
            null);

        ContentInfo contentInfo = new ContentInfo(SpcIndirectDataContent.ObjectIdentifier, dataContent.Encode());
        SignedCms signed = new SignedCms(contentInfo, false);
        signed.ComputeSignature(signer);
        return new Signature(signed, null);
    }

    private ReadOnlySpan<byte> DecodeUtf8Base64(ReadOnlySpan<byte> span)
    {
        //This method decodes the base64 inside a signature but also validates the format at the same time

        //Input:
        //<start-comment>MIIG6QYJKoZIhvcNAQcCoIIG2jCCBtYCAQExDjAMBggqhkiG9w0CBQUAMGgGCisG<end-comment>
        //<start-comment>pdcP2mPWgcj5SrZxJ+LXCuh5yw/hpngCNRc4eiC6oYvPWLL7VWh1sAxxKEl4<end-comment>

        int size = Base64.GetMaxDecodedFromUtf8Length(span.Length); //Length includes the comments, but it's fine.
        Span<byte> decoded = new byte[size];

        //We convert the comments to UTF-8 because we need to check them
        Span<byte> startComment = Encoding.UTF8.GetBytes(commentStart);
        Span<byte> endComment = Encoding.UTF8.GetBytes(commentEnd);
        Span<byte> newLine = Encoding.UTF8.GetBytes(TextContext.NewLine);

        int totalWritten = 0;
        int idx = 0;

        while (idx < span.Length)
        {
            //Check and then advance idx by start-comment
            ReadOnlySpan<byte> segment = span.Slice(idx, startComment.Length);
            if (!segment.SequenceEqual(startComment))
                throw new InvalidDataException("Invalid start comment.");

            idx += segment.Length;

            //Read 64 bytes of base64
            int toRead = Math.Min(span.Length - idx - endComment.Length, 64);
            segment = span.Slice(idx, toRead);

            if (Base64.DecodeFromUtf8(segment, decoded[totalWritten..], out _, out int bytesWritten) == OperationStatus.Done)
                totalWritten += bytesWritten;
            else
                throw new InvalidDataException("Invalid Base64 data.");

            idx += segment.Length;

            //Check and then advance idx by end-comment
            segment = span.Slice(idx, endComment.Length);
            if (!segment.SequenceEqual(endComment))
                throw new InvalidDataException("Invalid comment in data.");

            idx += segment.Length;

            //We might be at the very last line that does not have a newline
            if (idx >= span.Length)
                break;

            //Check and then advance idx by a newline
            segment = span.Slice(idx, newLine.Length);
            if (!segment.SequenceEqual(newLine))
                throw new InvalidDataException("Invalid newline in data.");

            idx += newLine.Length;
        }

        return decoded[..totalWritten];
    }
}