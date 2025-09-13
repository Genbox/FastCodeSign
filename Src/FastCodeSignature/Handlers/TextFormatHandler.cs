using System.Buffers;
using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Genbox.FastCodeSignature.Abstracts;
using Genbox.FastCodeSignature.Internal.Extensions;
using Genbox.FastCodeSignature.Internal.Helpers;
using Genbox.FastCodeSignature.Internal.WinPe.Spc;

namespace Genbox.FastCodeSignature.Handlers;

public abstract class TextFormatHandler(X509Certificate2 cert, string commentStart, string commentEnd, Encoding fallbackEncoding, string extension) : IFormatHandler
{
    private const string MagicHeader = "SIG # Begin signature block";
    private const string MagicFooter = "SIG # End signature block";

    private const string NewLine = "\r\n";
    private static readonly byte[] Utf8Bom = [0xEF, 0xBB, 0xBF];
    private static readonly byte[] Utf16Bom = [0xFF, 0xFE];

    //Technically, an empty file is valid
    public bool IsValid(ReadOnlySpan<byte> data, string? ext) => ext == null || ext == extension;

    public ReadOnlySpan<byte> ExtractSignature(ReadOnlySpan<byte> data)
    {
        TextFileContext context = GetContext(data);

        if (context.HeaderIdx == -1 || context.FooterIdx == -1) // Not signed
            return ReadOnlySpan<byte>.Empty;

        //If there is a signature, we expect it to contain something
        if (context.HeaderIdx >= 0 && context.FooterIdx >= 0)
        {
            //We expect <start-comment><base64><end-comment><newline>
            // - <base64> must be at least 4 chars long
            // - <newline> must be at least 2 chars long
            int minSize = commentStart.Length + 4 + commentEnd.Length + 2;

            if (Equals(context.Encoding, Encoding.Unicode))
                minSize *= 2;

            if (context.FooterIdx - context.HeaderIdx < minSize)
                return ReadOnlySpan<byte>.Empty;

            //There must not be anything after the signature
            int dataLength = data.Length - context.FooterIdx;
            if (dataLength != 0)
                return ReadOnlySpan<byte>.Empty;
        }

        //Get the base64 content of the signature (includes comments)
        ReadOnlySpan<byte> span = data[(context.HeaderIdx + context.HeaderSig.Length)..(context.FooterIdx - context.FooterSig.Length)];

        //The signature is always within the ASCII range, so if we have a UTF-16 encoding, let's convert the span to UTF-8.
        if (context.Encoding.Equals(Encoding.Unicode))
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

    public byte[] ComputeHash(ReadOnlySpan<byte> data, HashAlgorithmName hashAlgorithm)
    {
        TextFileContext context = GetContext(data);

        //If the data is signed, we omit the signature
        if (context.HeaderIdx >= 0 && context.FooterIdx >= 0)
            data = data[..context.HeaderIdx];

        //If the input data is UTF8, we need to convert it to UTF16.
        if (context.Encoding.Equals(Encoding.UTF8))
            data = Encoding.Unicode.GetBytes(Encoding.UTF8.GetString(data)); //TODO: This is not the most efficient way to do this.

        using IncrementalHash hasher = IncrementalHash.CreateHash(hashAlgorithm);
        hasher.AppendData(data);
        return hasher.GetHashAndReset();
    }

    public long RemoveSignature(Span<byte> data)
    {
        TextFileContext context = GetContext(data);

        if (context.HeaderIdx == -1 || context.FooterIdx == -1) // Not signed or invalid signature
            return 0;

        return context.HeaderIdx;
    }

    public void WriteSignature(IAllocation allocation, Signature signature)
    {
        Span<byte> data = allocation.GetSpan();

        TextFileContext context = GetContext(data);
        Span<byte> startComment = context.Encoding.GetBytes(commentStart);
        Span<byte> endComment = context.Encoding.GetBytes(commentEnd);
        Span<byte> newLine = context.Encoding.GetBytes(NewLine);

        byte[] encoded = signature.SignedCms.Encode();

        int base64Length = Base64.GetMaxEncodedToUtf8Length(encoded.Length);

        Span<byte> base64 = base64Length < 2048 ? stackalloc byte[base64Length] : new byte[base64Length];

        if (Base64.EncodeToUtf8(encoded, base64, out _, out int written) != OperationStatus.Done)
            throw new InvalidOperationException("Failed to encode signature");

        //In case the buffer was larger than needed
        base64 = base64[..written];

        if (context.Encoding.Equals(Encoding.Unicode))
            base64 = context.Encoding.GetBytes(Encoding.UTF8.GetString(base64)); //TODO: This is not the most efficient way to do this.

        int idx;

        if (context.HeaderIdx == -1 || context.FooterIdx == -1) // Not signed
            idx = data.Length;
        else
            idx = context.HeaderIdx;

        int headersLen = context.HeaderSig.Length + context.FooterSig.Length; // Space for header/footer (already includes comments and newlines)
        int commentLen = ((commentStart.Length + commentEnd.Length + newLine.Length) * (((base64Length + 64) - 1) / 64)) - newLine.Length; // space for comments

        allocation.SetLength((uint)(idx + headersLen + commentLen + base64.Length));

        //Get a new span with the updated length
        data = allocation.GetSpan();

        //Write the header (includes comment)
        context.HeaderSig.CopyTo(data[idx..]);
        idx += context.HeaderSig.Length;

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
        context.FooterSig.CopyTo(data[idx..]);
    }

    public bool TryGetHash(SignedCms signedCms, [NotNullWhen(true)]out byte[]? digest, out HashAlgorithmName algo)
    {
        SpcIndirectDataContent indirect = SpcIndirectDataContent.Decode(signedCms.ContentInfo.Content);
        digest = indirect.Digest;
        algo = OidHelper.OidToHashAlgorithm(indirect.DigestAlgorithm.Value!);
        return true;
    }

    public Signature CreateSignature(ReadOnlySpan<byte> data, HashAlgorithmName hashAlgorithm)
    {
        CmsSigner signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, cert)
        {
            DigestAlgorithm = hashAlgorithm.ToOid()
        };

        byte[] hash = ComputeHash(data, hashAlgorithm);

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

    private static Encoding? DetectEncoding(ReadOnlySpan<byte> data)
    {
        //Check for BOM
        if (data.StartsWith(Utf8Bom))
            return Encoding.UTF8;

        if (data.StartsWith(Utf16Bom))
            return Encoding.Unicode;

        //Fallback to finding the header with different encodings
        if (data.IndexOf(Encoding.UTF8.GetBytes(MagicHeader)) >= 0)
            return Encoding.UTF8;

        if (data.IndexOf(Encoding.Unicode.GetBytes(MagicHeader)) >= 0)
            return Encoding.Unicode;

        return null;
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
        Span<byte> newLine = Encoding.UTF8.GetBytes(NewLine);

        int totalWritten = 0;
        int idx = 0;

        while (idx < span.Length)
        {
            //Check and then advance idx by start-comment
            ReadOnlySpan<byte> segment = span.Slice(idx, startComment.Length);
            if (!segment.SequenceEqual(startComment))
                return ReadOnlySpan<byte>.Empty;

            idx += segment.Length;

            //Read 64 bytes of base64
            int toRead = Math.Min(span.Length - idx - endComment.Length, 64);
            segment = span.Slice(idx, toRead);

            if (Base64.DecodeFromUtf8(segment, decoded[totalWritten..], out _, out int bytesWritten) == OperationStatus.Done)
                totalWritten += bytesWritten;
            else
                return ReadOnlySpan<byte>.Empty;

            idx += segment.Length;

            //Check and then advance idx by end-comment
            segment = span.Slice(idx, endComment.Length);
            if (!segment.SequenceEqual(endComment))
                return ReadOnlySpan<byte>.Empty;

            idx += segment.Length;

            //We might be at the very last line that does not have a newline
            if (idx >= span.Length)
                break;

            //Check and then advance idx by a newline
            segment = span.Slice(idx, newLine.Length);
            if (!segment.SequenceEqual(newLine))
                return ReadOnlySpan<byte>.Empty;

            idx += newLine.Length;
        }

        return decoded[..totalWritten];
    }

    private TextFileContext GetContext(ReadOnlySpan<byte> data)
    {
        Encoding encoding = DetectEncoding(data) ?? fallbackEncoding;

        Span<byte> buffer = stackalloc byte[150];

        //We include newlines to be strict in the format
        int headerWritten = encoding.GetBytes(NewLine + commentStart + MagicHeader + commentEnd + NewLine, buffer);
        byte[] header = buffer[..headerWritten].ToArray();

        int footerWritten = encoding.GetBytes(NewLine + commentStart + MagicFooter + commentEnd + NewLine, buffer);
        byte[] footer = buffer[..footerWritten].ToArray();

        //When Windows append the signature, they include a newline before/after the signature.
        //We set the being/end pointer to encase the entire signature, including newlines.
        //This is so that we are strict in our handling of the signature (avoids security issues).
        //As a bonus, RemoveSignature() can just remove the blob with no extra logic.
        //
        //Example of signature:

        //Write-Host "Hello world"
        //[begin]
        //# SIG # Begin signature block
        //# MIIG6QYJKoZIhvcNAQcCoIIG2jCCBtYCAQExDjAMBggqhkiG9w0CBQUAMGgGCisG
        //# pdcP2mPWgcj5SrZxJ+LXCuh5yw/hpngCNRc4eiC6oYvPWLL7VWh1sAxxKEl4
        //# SIG # End signature block
        //[emd]

        int headerIdx = data.IndexOf(header);
        int footerIdx = -1;

        //Look for footerIdx AFTER headerIdx (avoids signature confusion and helps perf)
        //We also take the LAST index to prevent signature confusion (duplicate end markers)
        if (headerIdx >= 0)
            footerIdx = data[headerIdx..].LastIndexOf(footer);

        if (footerIdx >= 0)
        {
            footerIdx += headerIdx; //Convert end index to absolute index
            footerIdx += footerWritten; //Move index to after signature
        }

        return new TextFileContext
        {
            HeaderIdx = headerIdx,
            HeaderSig = header,
            FooterIdx = footerIdx,
            FooterSig = footer,
            Encoding = encoding
        };
    }

    [StructLayout(LayoutKind.Auto)]
    private readonly ref struct TextFileContext
    {
        internal int HeaderIdx { get; init; }
        internal byte[] HeaderSig { get; init; }
        internal int FooterIdx { get; init; }
        internal byte[] FooterSig { get; init; }
        internal Encoding Encoding { get; init; }
    }
}