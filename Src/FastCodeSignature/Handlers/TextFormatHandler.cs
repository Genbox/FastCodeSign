using System.Buffers;
using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Genbox.FastCodeSignature.Abstracts;
using Genbox.FastCodeSignature.Internal;
using Genbox.FastCodeSignature.Internal.Extensions;
using Genbox.FastCodeSignature.Internal.Helpers;
using Genbox.FastCodeSignature.Internal.TextFile;
using Genbox.FastCodeSignature.Internal.WinPe.Spc;
using Genbox.FastCodeSignature.Models;

namespace Genbox.FastCodeSignature.Handlers;

[SuppressMessage("Design", "CA1033:Interface methods should be callable by child types")]
public abstract class TextFormatHandler(string commentStart, string commentEnd, Encoding? fallbackEncoding) : IFormatHandler
{
    private const int PerLineChars = 64;

    public abstract int MinValidSize { get; }
    public abstract string[] ValidExt { get; }
    public abstract bool IsValidHeader(ReadOnlySpan<byte> data);

    IContext IFormatHandler.GetContext(ReadOnlySpan<byte> data) => TextContext.Create(data, commentStart, commentEnd, fallbackEncoding ?? Encoding.UTF8);

    public ReadOnlySpan<byte> ExtractSignature(IContext context, ReadOnlySpan<byte> data)
    {
        TextContext obj = (TextContext)context;

        //Get the base64 content of the signature (includes comments)
        ReadOnlySpan<byte> span = data[(obj.HeaderIdx + obj.HeaderSig.Length)..(obj.FooterIdx - obj.FooterSig.Length)];

        //The signature is always within the ASCII range, so if we have a UTF-16 encoding, let's convert the span to UTF-8.
        if (obj.Encoding.CodePage == 1200)
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

    byte[] IFormatHandler.ComputeHash(IContext context, ReadOnlySpan<byte> data, HashAlgorithmName hashAlgorithm)
    {
        TextContext obj = (TextContext)context;

        //If the data is signed, we omit the signature
        if (context.IsSigned)
            data = data[..obj.HeaderIdx];

        //If the input data is UTF8, we need to convert it to UTF16.
        if (obj.Encoding.CodePage == 65001) // input UTF-8, hashing over UTF-16
            data = Encoding.Convert(Encoding.UTF8, Encoding.Unicode, data.ToArray());

        using IncrementalHash hasher = IncrementalHash.CreateHash(hashAlgorithm);
        hasher.AppendData(data);
        return hasher.GetHashAndReset();
    }

    long IFormatHandler.RemoveSignature(IContext context, Span<byte> data)
    {
        TextContext obj = (TextContext)context;
        return obj.FooterIdx - obj.HeaderIdx;
    }

    void IFormatHandler.WriteSignature(IContext context, IAllocation allocation, Signature signature)
    {
        TextContext obj = (TextContext)context;
        Span<byte> startComment = obj.Encoding.GetBytes(commentStart);
        Span<byte> endComment = obj.Encoding.GetBytes(commentEnd);
        Span<byte> newLine = obj.Encoding.GetBytes(TextContext.NewLine);

        byte[] encoded = signature.SignedCms.Encode();

        if (obj.Encoding.CodePage == 1200)
            WriteUtf16(obj, allocation, startComment, endComment, newLine, encoded);
        else if (obj.Encoding.CodePage == 65001)
            WriteUtf8(obj, allocation, startComment, endComment, newLine, encoded);
        else
            throw new InvalidOperationException("Invalid encoding: " + obj.Encoding.CodePage);
    }

    private static void WriteUtf8(TextContext obj, IAllocation allocation, ReadOnlySpan<byte> startComment, ReadOnlySpan<byte> endComment, ReadOnlySpan<byte> newLine, byte[] encoded)
    {
        int base64Len = ((encoded.Length + 2) / 3) * 4;
        Span<byte> base64 = base64Len <= 2048 ? stackalloc byte[base64Len] : new byte[base64Len];

        if (Base64.EncodeToUtf8(encoded, base64, out _, out int written) != OperationStatus.Done)
            throw new InvalidOperationException("Failed to encode signature");

        base64 = base64[..written];

        int lineCount = (base64.Length + PerLineChars - 1) / PerLineChars;

        int headersLen = obj.HeaderSig.Length + obj.FooterSig.Length;
        int commentLen = ((startComment.Length + endComment.Length + newLine.Length) * lineCount) - newLine.Length; // no trailing newline after last line

        Span<byte> ext = allocation.CreateExtension((uint)(headersLen + commentLen + base64.Length));

        int idx = 0;

        // Write header
        obj.HeaderSig.CopyTo(ext[idx..]);
        idx += obj.HeaderSig.Length;

        int base64Rem = base64.Length;
        int base64Offset = 0;

        while (base64Rem > 0)
        {
            // Write start comment
            startComment.CopyTo(ext[idx..]);
            idx += startComment.Length;

            int toWrite = Math.Min(base64Rem, PerLineChars);
            base64.Slice(base64Offset, toWrite).CopyTo(ext[idx..]);
            idx += toWrite;

            if (endComment.Length > 0)
            {
                endComment.CopyTo(ext[idx..]);
                idx += endComment.Length;
            }

            base64Rem -= toWrite;
            base64Offset += toWrite;

            if (base64Rem > 0)
            {
                //Write newline
                newLine.CopyTo(ext[idx..]);
                idx += newLine.Length;
            }
        }

        // Write footer
        obj.FooterSig.CopyTo(ext[idx..]);
    }

    private static void WriteUtf16(TextContext obj, IAllocation allocation, ReadOnlySpan<byte> startComment, ReadOnlySpan<byte> endComment, ReadOnlySpan<byte> newLine, byte[] encoded)
    {
        int base64CharLen = ((encoded.Length + 2) / 3) * 4;
        Span<char> base64Chars = base64CharLen <= 2048 ? stackalloc char[base64CharLen] : new char[base64CharLen];

        if (!Convert.TryToBase64Chars(encoded, base64Chars, out int charsWritten))
            throw new InvalidOperationException("Failed to encode signature");

        base64Chars = base64Chars[..charsWritten];

        int lineCount = (charsWritten + PerLineChars - 1) / PerLineChars;

        // We will write the Base64 chars encoded as UTF-16 bytes. Compute the total byte count for the Base64 payload up front.
        int b64ByteLen = obj.Encoding.GetByteCount(base64Chars);

        int headersLen = obj.HeaderSig.Length + obj.FooterSig.Length;
        int commentLen = ((startComment.Length + endComment.Length + newLine.Length) * lineCount) - newLine.Length; // no trailing newline after last line

        Span<byte> ext = allocation.CreateExtension((uint)(headersLen + commentLen + b64ByteLen));

        int idx = 0;

        // Write header
        obj.HeaderSig.CopyTo(ext[idx..]);
        idx += obj.HeaderSig.Length;

        int base64Rem = base64Chars.Length;
        int base64Offset = 0;

        while (base64Rem > 0)
        {
            // Write start comment
            startComment.CopyTo(ext[idx..]);
            idx += startComment.Length;

            int toWrite = Math.Min(base64Rem, PerLineChars);

            // Encode this 64-char (or tail) chunk into UTF-16 bytes directly into output
            ReadOnlySpan<char> chunk = base64Chars.Slice(base64Offset, toWrite);
            int bytesWritten = obj.Encoding.GetBytes(chunk, ext[idx..]);
            idx += bytesWritten;

            if (endComment.Length > 0)
            {
                endComment.CopyTo(ext[idx..]);
                idx += endComment.Length;
            }

            base64Rem -= toWrite;
            base64Offset += toWrite;

            if (base64Rem > 0)
            {
                // Write newline
                newLine.CopyTo(ext[idx..]);
                idx += newLine.Length;
            }
        }

        // Write footer
        obj.FooterSig.CopyTo(ext[idx..]);
    }

    bool IFormatHandler.ExtractHashFromSignedCms(SignedCms signedCms, [NotNullWhen(true)]out byte[]? digest, out HashAlgorithmName algo)
    {
        SpcIndirectDataContent indirect = SpcIndirectDataContent.Decode(signedCms.ContentInfo.Content);
        digest = indirect.Digest;
        algo = OidHelper.OidToHashAlgorithm(indirect.DigestAlgorithm.Value!);
        return true;
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
            new SpcSipInfo(65536, SpcSipInfo.SecurityProviderGuid).Encode(),
            SpcSipInfo.ObjectIdentifier,
            signer.DigestAlgorithm,
            hash,
            null);

        ContentInfo contentInfo = new ContentInfo(SpcIndirectDataContent.ObjectIdentifier, dataContent.Encode());
        SignedCms signed = new SignedCms(contentInfo, false);
        signed.ComputeSignature(signer, silent);
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