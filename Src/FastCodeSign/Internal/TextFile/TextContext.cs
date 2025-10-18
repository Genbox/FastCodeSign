using System.Text;
using Genbox.FastCodeSign.Abstracts;

namespace Genbox.FastCodeSign.Internal.TextFile;

internal sealed class TextContext : IContext
{
    private static readonly byte[] Utf8Bom = [0xEF, 0xBB, 0xBF];
    private static readonly byte[] Utf16Bom = [0xFF, 0xFE];
    private const string MagicHeader = "SIG # Begin signature block";
    private const string MagicFooter = "SIG # End signature block";
    internal const string NewLine = "\r\n";

    public static TextContext Create(ReadOnlySpan<byte> data, string commentStart, string commentEnd, Encoding fallbackEncoding)
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

        bool isSigned = headerIdx != -1 && footerIdx != -1;

        if (isSigned)
        {
            //We expect <start-comment><base64><end-comment><newline>
            // - <base64> must be at least 4 chars long
            // - <newline> must be at least 2 chars long
            int minSize = commentStart.Length + 4 + commentEnd.Length + 2;

            if (Equals(encoding, Encoding.Unicode))
                minSize *= 2;

            if (footerIdx - headerIdx < minSize)
                throw new InvalidDataException("The signature length is too small.");

            //There must not be anything after the signature
            if (data.Length - footerIdx != 0)
                throw new InvalidDataException("There is data after the signature.");
        }

        return new TextContext
        {
            IsSigned = isSigned,
            HeaderIdx = headerIdx,
            HeaderSig = header,
            FooterIdx = footerIdx,
            FooterSig = footer,
            Encoding = encoding
        };
    }

    public required bool IsSigned { get; init; }
    internal required int HeaderIdx { get; init; }
    internal required byte[] HeaderSig { get; init; }
    internal required int FooterIdx { get; init; }
    internal required byte[] FooterSig { get; init; }
    internal required Encoding Encoding { get; init; }

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
}