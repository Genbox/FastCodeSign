using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Genbox.FastCodeSign.Native.Authenticode;

namespace Genbox.Tools.Win.CreatePowerShellFiles;

// This tool is able to create a set of test vectors used for checking the correctness of the PowerShell handler
// It also creates an unsigned and signed version of a simple powershell script.

internal static class Program
{
    private const string BeginMarker = "# SIG # Begin signature block";
    private const string EndMarker = "# SIG # End signature block";
    private const string NewLine = "\r\n";
    private static readonly string[] NewLineArr = [NewLine];

    private static void Main()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("This tool only runs on Windows");

        X509Certificate2 cert = X509CertificateLoader.LoadPkcs12FromFile("FastCodeSign.pfx", "password");

        //The default PS1 file is UTF8 without BOM, and CRLF newlines.
        RSA rsa = cert.GetRSAPrivateKey()!;
        HashAlgorithmName hash = HashAlgorithmName.SHA256;

        foreach (string file in Directory.GetFiles("PowerShell", "*_unsigned.dat", SearchOption.TopDirectoryOnly))
        {
            SignFile(file, cert, rsa, hash);
        }

        const string vectorsDir = "TestVectors";

        if (!Directory.Exists(vectorsDir))
            Directory.CreateDirectory(vectorsDir);

        Console.WriteLine("Creating test vectors");
        GeneratePowerShellNormal(File.ReadAllText("PowerShell/ps1_unsigned.dat"), cert, vectorsDir);
        GeneratePowerShellEdgeCases(File.ReadAllText("PowerShell/ps1_signed.dat"), vectorsDir);
    }

    private static void SignFile(string unsigned, X509Certificate2 cert, RSA rsa, HashAlgorithmName hash, TimeStampConfiguration? timeConfig = null)
    {
        Console.WriteLine($"Signing {unsigned}");

        //Get the extension (needed by authenticode to determine SIP provider)
        string name = Path.GetFileName(unsigned);
        string ext = name[..name.IndexOf('_', StringComparison.Ordinal)];

        string signed = $"{unsigned.Replace("unsigned", "signed", StringComparison.Ordinal)}.{ext}";
        File.Copy(unsigned, signed, true);
        AuthenticodeSigner.SignFile(signed, cert, rsa, hash, timeConfig);

        //Rename the file back to .dat now that it is signed
        string newName = signed[..signed.LastIndexOf('.')];
        File.Move(signed, newName, true);
    }

    private static void GeneratePowerShellEdgeCases(string signedContent, string outDir)
    {
        (string edgeCaseName, Func<string, string> edgeCase)[] edgeCases =
        [
            ("invalid-format_add-space-before-comment", s => s.Replace("#", " #", StringComparison.Ordinal)),
            ("invalid-format_remove-space-after-comment", s => s.Replace("# ", "#", StringComparison.Ordinal)),
            ("invalid-format_tab-after-comment", s => s.Replace("# ", "#\t", StringComparison.Ordinal)),
            ("invalid-format_remove-cr-from-crlf", s => s.Replace(NewLine, "\n", StringComparison.Ordinal)),
            ("invalid-format_remove-lf-from-crlf", s => s.Replace(NewLine, "\r", StringComparison.Ordinal)),
            ("invalid-format_add-space-before-crlf", s => s.Replace(NewLine, " \r\n", StringComparison.Ordinal)),

            // Comment-prefix & whitespace variants (inside base64 lines)
            ("invalid-format_nbsp-after-comment", s => ReplacePrefix(s, "#\u00A0")),
            ("invalid-format_emspace-after-hash", s => Transform(s, lines => lines.Select(l => l.StartsWith("# ", StringComparison.Ordinal) && !IsMarker(l) ? "#" + "\u2003" + l[2..] : l))),
            ("invalid-format_fullwidth-hash-prefix", s => Transform(s, lines => lines.Select(l => l.StartsWith("# ", StringComparison.Ordinal) && !IsMarker(l) ? "\uFF03 " + l[2..] : l))),
            ("invalid-format_trailing-spaces-in-block", s => TrailingSpacesInBlock(s)),
            ("invalid-format_extra-blank-comment-lines-8", s => InsertBlankBase64Lines(s)),
            ("invalid-format_true-blank-lines-inside-block", TrueBlankLinesInBlock),
            ("invalid-format_indented-base64-lines-12", s => Transform(s, lines => lines.Select(l => IsB64(l) ? "            " + l : l))), // 12 spaces
            ("invalid-format_tabs-inside-base64", s => TabsInsideBase64(s)),
            ("invalid-format_zwsp-in-base64", ZeroWidthSpaceInBase64),
            ("invalid-format_hash-in-base64", HashInjectedInBase64),
            ("invalid-format_urlsafe-base64", UrlSafeB64),
            ("invalid-format_strip-base64-padding", StripPaddingB64),
            ("invalid-format_extra-base64-padding", ExtraPaddingB64),
            ("invalid-format_control-ws-in-base64", ControlWsInB64),
            ("invalid-format_bom-inside-first-b64-line", BomInsideFirstB64),
            ("invalid-format_nulls-in-base64", NullsInB64),

            // Base64 line layout
            ("invalid-format_single-line-base64", CollapseBase64ToSingleLine),
            ("invalid-format_super-long-single-b64-x5", s => // repeat payload 5× on one line
            {
                string once = CollapseBase64ToSingleLine(s);
                string[] lines = once.Split(NewLineArr, StringSplitOptions.None);
                for (int i = 0; i < lines.Length; i++)
                {
                    if (IsB64(lines[i]))
                    {
                        string p = lines[i][2..];
                        lines[i] = "# " + string.Concat(Enumerable.Repeat(p, 5));
                        break;
                    }
                }
                return string.Join(NewLine, (IEnumerable<string>)lines);
            }),

            // Marker mutations
            ("invalid-format_lowercase-markers", LowercaseMarkers),
            ("invalid-format_indent-markers-4", s => IndentMarkers(s)),
            ("invalid-format_markers-extra-spaces", MarkersExtraSpaces),
            ("invalid-format_markers-homoglyph-sig", MarkersHomoglyphSig),
            ("invalid-format_markers-directionality-marks", MarkersWithBiDi),
            ("invalid-format_titlecase-markers", WithTitleCaseMarkers),
            ("invalid-format_misspell-end-marker", MisspellEnd),
            ("invalid-format_trailing-garbage-after-begin", TrailingGarbageAfterBegin),
            ("invalid-format_duplicate-begin-marker", DuplicateBegin),
            ("invalid-format_duplicate-end-marker", DuplicateEnd),
            ("invalid-format_garbage-after-end", GarbageAfterEnd),
            ("invalid-format_blank-lines-around-markers", BlankAroundMarkers),
            ("invalid-format_bare-text-markers", TitlelessMarkers),
            ("invalid-format_block-comment-markers", BlockCommentWrapper),

            // Newline mutations (inside the block string)
            ("invalid-format_mixed-crlf-inside-block", MixedCrLfInside),
            ("invalid-format_unicode-line-separator-U+2028", s => s.ReplaceLineEndings("\u2028")),
            ("invalid-format_unicode-NEL-U+0085", s => s.ReplaceLineEndings("\u0085")),

            // Multi / nested / multiple blocks (concatenate variants)
            ("invalid-format_two-blocks-first-invalid", s => CorruptFirstBase64Char(s) + NewLine + s),
            ("invalid-format_two-blocks-last-invalid", s => s + NewLine + CorruptFirstBase64Char(s)),
            ("invalid-format_two-identical-valid-blocks", s => s + NewLine + s),
            ("invalid-format_three-valid-blocks", s => s + NewLine + s + NewLine + s),
            ("invalid-format_nested-begin-begin-end-end", Nested_BeginBegin_EndEnd),
            ("invalid-format_interleaved-two-blocks", Interleaved_TwoBlocks),
            ("invalid-format_crossed-markers-partial-then-begin", Crossed_PartialThenBegin),
            ("invalid-format_begin-inside-b64-then-end-then-valid", BeginInsideB64_ThenEnd_ThenValid),

            // Foreign lines inside (non-comment or comment noise)
            ("invalid-format_foreign-noncomment-inside-then-valid", s =>
            {
                List<string> lines = s.Split(NewLineArr, StringSplitOptions.None).ToList();
                int firstB64 = lines.FindIndex(IsB64);
                if (firstB64 > 0) lines.Insert(Math.Min(firstB64 + 5, lines.Count - 1), "Write-Host 'oops inside'");
                string broken = string.Join(NewLine, lines);
                return broken + NewLine + s;
            }),
            ("invalid-format_foreign-comment-inside-then-valid", s =>
            {
                List<string> lines = s.Split(NewLineArr, StringSplitOptions.None).ToList();
                int firstB64 = lines.FindIndex(IsB64);
                if (firstB64 > 0) lines.Insert(Math.Min(firstB64 + 5, lines.Count - 1), "# not-a-b64");
                string broken = string.Join(NewLine, lines);
                return broken + NewLine + s;
            }),
            // Unicode space variants after '#'
            ("invalid-format_thinspace-after-hash", s => MapB64(s, l => "#\u2009" + l[2..])),
            ("invalid-format_enspace-after-hash", s => MapB64(s, l => "#\u2002" + l[2..])),
            ("invalid-format_figurespace-after-hash", s => MapB64(s, l => "#\u2007" + l[2..])),

            // Leading indentation with non-breaking space
            ("invalid-format_leading-nbsp-before-hash", s => Transform(s, lines =>
            {
                for (int i = 0; i < lines.Length; i++)
                    if (IsB64(lines[i]))
                        lines[i] = "\u00A0" + lines[i];
                return lines;
            })),

            // Alternate comment sigils
            ("invalid-format_double-hash-prefix", s => MapB64(s, l => "## " + l[2..])),
            ("invalid-format_small-number-sign-prefix", s => MapB64(s, l => "\uFE5F " + l[2..])), // U+FE5F SMALL NUMBER SIGN

            // Trailing oddities on base64 lines
            ("invalid-format_trailing-nbsp-in-b64", s => MapB64(s, l => l + "\u00A0")),
            ("invalid-format_trailing-tab-in-b64", s => MapB64(s, l => l + "\t")),
            ("invalid-format_trailing-vert-tab-in-b64", s => MapB64(s, l => l + "\v")),
            ("invalid-format_suffix-comment-after-b64", s => MapB64(s, l => l + " # trailing")),

            // Backticks at end of each base64 line
            ("invalid-format_backtick-suffix-each-b64", s => MapB64(s, l => l + " `")),

            // Reordering of base64 lines
            ("invalid-format_reverse-b64-line-order", s => ReplaceB64Seq(s, seq =>
            {
                seq.Reverse();
                return seq;
            })),

            // Append extra base64-looking garbage lines
            ("invalid-format_append-extra-b64-gibberish-5", s => InsertAfterLastB64(s, Enumerable.Range(0, 5).Select(_ => "# " + new string('A', 64)))),

            // Blank lines outside the block content
            ("invalid-format_post-end-blanklines-3", s => s + "\r\n\r\n\r\n"),

            // Marker line perturbations
            ("invalid-format_markers-with-trailing-tabs", s => Transform(s, lines =>
            {
                for (int i = 0; i < lines.Length; i++)
                    if (IsMarker(lines[i]))
                        lines[i] += "\t\t";
                return lines;
            })),
            ("invalid-format_markers-with-trailing-comment", s => Transform(s, lines =>
            {
                for (int i = 0; i < lines.Length; i++)
                    if (IsMarker(lines[i]))
                        lines[i] += " # marker";
                return lines;
            })),
            ("invalid-format_markers-uppercase", s => Transform(s, lines =>
            {
                for (int i = 0; i < lines.Length; i++)
                    if (IsMarker(lines[i]))
                        lines[i] = lines[i].ToUpperInvariant();
                return lines;
            })),
            ("invalid-format_markers-no-hash-space", s => Transform(s, lines =>
            {
                for (int i = 0; i < lines.Length; i++)
                {
                    if (lines[i] == BeginMarker) lines[i] = "#SIG # Begin signature block";
                    else if (lines[i] == EndMarker) lines[i] = "#SIG # End signature block";
                }
                return lines;
            })),
            ("invalid-format_markers-with-bom", s => Transform(s, lines =>
            {
                for (int i = 0; i < lines.Length; i++)
                    if (IsMarker(lines[i]))
                        lines[i] = "\uFEFF" + lines[i];
                return lines;
            })),

            // Invisible chars wrapped around base64 payloads
            ("invalid-format_word-joiner-after-prefix", s => MapB64(s, l => "# \u2060" + l[2..])), // U+2060 WORD JOINER
            ("invalid-format_bidi-embed-around-b64", s => MapB64(s, l => "# \u202A" + l[2..] + "\u202C")), // LRE ... PDF

            // Extreme splitting: one base64 char per line
            ("invalid-format_one-char-per-b64-line", s =>
            {
                string[] lines = s.Split(NewLineArr, StringSplitOptions.None);
                string payload = string.Concat(lines.Where(IsB64).Select(l => l[2..]));
                List<string> rebuilt = new List<string> { lines[0] };
                foreach (char ch in payload) rebuilt.Add("# " + ch);
                rebuilt.Add(lines[^1]);
                return string.Join(NewLine, rebuilt);
            }),

            // Heavy indentation variants
            ("invalid-format_indented-b64-lines-tabs-3", s => Transform(s, lines =>
            {
                for (int i = 0; i < lines.Length; i++)
                    if (IsB64(lines[i]))
                        lines[i] = "\t\t\t" + lines[i];
                return lines;
            })),
            ("invalid-format_indented-b64-lines-4096", s => Transform(s, lines =>
            {
                string pad = new string(' ', 4096);
                for (int i = 0; i < lines.Length; i++)
                    if (IsB64(lines[i]))
                        lines[i] = pad + lines[i];
                return lines;
            })),

            // DOS EOF marker after End
            ("invalid-format_ctrl-z-after-end", s => s + "\x1A"),
            ("invalid-format_insert-b64-before-end", InsertB64BeforeEnd),

            ("invalid-signature_end-before-begin-then-valid", EndBeforeBegin_ThenValid),
            ("invalid-signature_begin-end-same-line-then-valid", BeginEndSameLine_ThenValid),
            ("invalid-signature_end-then-begin-immediately", EndThenBegin_Inline),

            ("invalid-base64_drop-last-b64-line", s => ReplaceB64Seq(s, seq => seq.Take(Math.Max(0, seq.Count - 1)).ToList())),
            ("invalid-base64_even-then-odd-b64-lines", s => ReplaceB64Seq(s, seq =>
            {
                List<string> even = new List<string>();
                List<string> odd = new List<string>();
                for (int i = 0; i < seq.Count; i++)
                    (i % 2 == 0 ? even : odd).Add(seq[i]);
                return even.Concat(odd).ToList();
            })),
            ("invalid-base64_drop-every-7th-b64-line", s => ReplaceB64Seq(s, seq => seq.Where((_, i) => (i + 1) % 7 != 0).ToList())),
            ("invalid-signature_pre-begin-blanklines-3", s => "\r\n\r\n\r\n" + s)
        ];

        //Extract the signature block
        int idx = signedContent.IndexOf(BeginMarker, StringComparison.Ordinal);

        if (idx == -1)
            throw new InvalidOperationException("Failed to find signature block");

        string beforeSignature = signedContent[..idx];
        string signatureBlock = signedContent[idx..];

        UTF8Encoding utfNoBom = new UTF8Encoding(false);
        foreach ((string edgeCaseName, Func<string, string> edgeCase) in edgeCases)
        {
            string newSignatureBlock = edgeCase(signatureBlock);
            string newContent = beforeSignature + newSignatureBlock;

            File.WriteAllText(Path.Combine(outDir, $"{edgeCaseName}.dat"), newContent, utfNoBom);
        }
    }

    private static void GeneratePowerShellNormal(string content, X509Certificate2 cert, string outDir)
    {
        (string newlineName, string newline)[] newLines =
        [
            ("crlf", NewLine),
            ("lf", "\n")
        ];

        (string encodingName, Encoding encoding)[] encodings =
        [
            ("utf8-bom", Encoding.UTF8),
            ("utf8", new UTF8Encoding(false)),
            ("utf16-bom", Encoding.Unicode),
            ("utf16", new UnicodeEncoding(false, false))
        ];

        (string, AsymmetricAlgorithm?)[] signatureAlgorithms =
        [
            ("RSA", cert.GetRSAPrivateKey())
        ];

        (string, HashAlgorithmName)[] digestAlgorithms =
        [
            ("MD5", HashAlgorithmName.MD5),
            ("SHA1", HashAlgorithmName.SHA1),
            ("SHA256", HashAlgorithmName.SHA256),
            ("SHA384", HashAlgorithmName.SHA384),
            ("SHA512", HashAlgorithmName.SHA512)
        ];

        foreach ((string encodingName, Encoding encoding) in encodings)
        {
            foreach ((string newlineName, string newline) in newLines)
            {
                foreach ((string signatureName, AsymmetricAlgorithm? signatureAlgorithm) in signatureAlgorithms)
                {
                    if (signatureAlgorithm == null)
                        throw new InvalidOperationException($"Signature algorithm {signatureName} is null");

                    foreach ((string digestName, HashAlgorithmName hashAlgorithmName) in digestAlgorithms)
                    {
                        string fileName = $"normal_{encodingName}_{newlineName}_{signatureName}_{digestName}.ps1";
                        string fullPath = Path.Combine(outDir, fileName);

                        content = content.ReplaceLineEndings(newline);
                        File.WriteAllText(fullPath, content, encoding);

                        AuthenticodeSigner.SignFile(fullPath, cert, signatureAlgorithm, hashAlgorithmName, null);

                        //Rename the file to dat (it must be ps1 for Windows to be able to sign it)
                        File.Move(fullPath, Path.ChangeExtension(fullPath, ".dat"));
                    }
                }
            }
        }
    }

    private static bool IsMarker(string l) => l.Contains("Begin signature block", StringComparison.Ordinal) || l.Contains("End signature block", StringComparison.Ordinal);
    private static bool IsB64(string l) => l.StartsWith("# ", StringComparison.Ordinal) && !IsMarker(l);

    private static string MapB64(string s, Func<string, string> map)
    {
        string[] lines = s.Split(NewLineArr, StringSplitOptions.None);
        for (int i = 1; i < lines.Length - 1; i++)
        {
            if (IsB64(lines[i]))
                lines[i] = map(lines[i]);
        }
        return string.Join(NewLine, (IEnumerable<string>)lines);
    }

    private static string Transform(string s, Func<string[], IEnumerable<string>> f) => string.Join(NewLine, f(s.Split(NewLineArr, StringSplitOptions.None)));

    private static string CorruptFirstBase64Char(string s, char repl = '!') => MapB64(s, l =>
    {
        int p = l.IndexOf('A', StringComparison.Ordinal);
        return p > 0 ? l[..p] + repl + l[(p + 1)..] : l;
    });

    private static string CollapseBase64ToSingleLine(string s) => Transform(s, lines =>
    {
        string payload = string.Concat(lines.Where(IsB64).Select(l => l[2..]));
        List<string> outLines = new List<string>(lines.Length);
        bool done = false;
        foreach (string l in lines)
        {
            if (IsB64(l))
            {
                if (!done)
                {
                    outLines.Add("# " + payload);
                    done = true;
                }
            }
            else outLines.Add(l);
        }
        return outLines;
    });

    private static string InsertBlankBase64Lines(string s, int every = 8) => Transform(s, lines =>
    {
        List<string> outLines = new List<string>(lines.Length + (lines.Length / 8));
        int n = 0;
        foreach (string l in lines)
        {
            outLines.Add(l);
            if (IsB64(l) && ++n % every == 0)
                outLines.Add("# ");
        }
        return outLines;
    });

    private static string MixedCrLfInside(string s)
    {
        string[] lines = s.Split(NewLineArr, StringSplitOptions.None);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < lines.Length; i++)
            sb.Append(lines[i]).Append(i % 2 == 0 ? NewLine : "\n");
        return sb.ToString();
    }

    private static string WithTitleCaseMarkers(string s) => Transform(s, lines => lines.Select(l =>
        l.Replace("Begin signature block", "Begin Signature Block", StringComparison.Ordinal)
         .Replace("End signature block", "End Signature Block", StringComparison.Ordinal)));

    private static string IndentMarkers(string s, int spaces = 4) => Transform(s, lines =>
    {
        string pad = new string(' ', spaces);
        for (int i = 0; i < lines.Length; i++)
        {
            if (IsMarker(lines[i]))
                lines[i] = pad + lines[i];
        }
        return lines;
    });

    private static string MarkersExtraSpaces(string s) => Transform(s, lines => lines.Select(l =>
        l.Replace("# SIG # Begin signature block", "# SIG   #   Begin   signature   block", StringComparison.Ordinal)
         .Replace("# SIG # End signature block", "# SIG   #   End   signature   block", StringComparison.Ordinal)));

    private static string MarkersHomoglyphSig(string s) => Transform(s, lines => lines.Select(l => l.Replace("SIG", "СІG", StringComparison.Ordinal))); // Cyrillic С(U+0421), І(U+0406)

    private static string MarkersWithBiDi(string s) => Transform(s, lines => lines.Select(l =>
    {
        if (l.Contains(BeginMarker, StringComparison.Ordinal) || l.Contains(EndMarker, StringComparison.Ordinal))
            return "\u200E" + l + "\u200F";
        return l;
    }));

    private static string MisspellEnd(string s) => Transform(s, lines => lines.Select(l => l.Contains(EndMarker, StringComparison.Ordinal)
        ? l.Replace("End signature block", "End signatureblock", StringComparison.Ordinal)
        : l));

    private static string TrailingGarbageAfterBegin(string s) => Transform(s, lines =>
    {
        for (int i = 0; i < lines.Length; i++)
        {
            if (lines[i].Contains(BeginMarker, StringComparison.Ordinal))
            {
                lines[i] += "    trailing-garbage";
                break;
            }
        }
        return lines;
    });

    private static string DuplicateBegin(string s) => Transform(s, lines =>
    {
        List<string> list = new List<string>(lines.Length + 1);
        bool duped = false;
        foreach (string l in lines)
        {
            list.Add(l);
            if (!duped && l.Contains(BeginMarker, StringComparison.Ordinal))
            {
                list.Add(l);
                duped = true;
            }
        }
        return list;
    });

    private static string DuplicateEnd(string s) => Transform(s, lines =>
    {
        List<string> list = new List<string>(lines);
        int idx = list.FindIndex(l => l.Contains(EndMarker, StringComparison.Ordinal));
        if (idx >= 0)
            list.Insert(idx + 1, EndMarker);
        return list;
    });

    private static string GarbageAfterEnd(string s) => Transform(s, lines =>
    {
        List<string> list = new List<string>(lines);
        int idx = list.FindIndex(l => l.Contains(EndMarker, StringComparison.Ordinal));
        if (idx >= 0)
            list.Insert(idx + 1, "# AAAAthisShouldNotBeHereAAAA");
        return list;
    });

    private static string BlankAroundMarkers(string s) => Transform(s, lines =>
    {
        List<string> outLines = new List<string>(lines.Length + 2);
        foreach (string line in lines)
        {
            if (line.Contains(BeginMarker, StringComparison.Ordinal))
            {
                outLines.Add(line);
                outLines.Add("");
            }
            else if (line.Contains(EndMarker, StringComparison.Ordinal))
            {
                outLines.Add("");
                outLines.Add(line);
            }
            else outLines.Add(line);
        }
        return outLines;
    });

    private static string LowercaseMarkers(string s) => Transform(s, lines => lines.Select(l =>
        l.Replace(BeginMarker, "# sig # begin signature block", StringComparison.Ordinal)
         .Replace(EndMarker, "# sig # end signature block", StringComparison.Ordinal)));

    private static string TitlelessMarkers(string s) => Transform(s, lines => lines.Select(l => l switch
    {
        BeginMarker => "SIG # Begin signature block",
        EndMarker => "SIG # End signature block",
        _ => l
    }));

    private static string BlockCommentWrapper(string s)
    {
        string[] lines = s.Split(NewLineArr, StringSplitOptions.None);
        IEnumerable<string> inner = lines.Skip(1).Take(lines.Length - 2).Select(l => l.StartsWith("# ", StringComparison.Ordinal) ? l[2..] : l);
        List<string> wrapped = ["<# SIG # Begin signature block"];
        wrapped.AddRange(inner);
        wrapped.Add("SIG # End signature block #>");
        return string.Join(NewLine, wrapped);
    }

    // comment prefix variants on base64 lines
    private static string ReplacePrefix(string s, string newPrefix) => MapB64(s, l =>
    {
        if (l.StartsWith("# ", StringComparison.Ordinal)) return newPrefix + l[2..];
        if (l.StartsWith("#\t", StringComparison.Ordinal)) return newPrefix + l[2..];
        if (l.StartsWith("#\u00A0", StringComparison.Ordinal)) return newPrefix + l[2..];
        if (l.StartsWith('#')) return newPrefix + l[1..];
        return l;
    });

    private static string TrailingSpacesInBlock(string s, int spaces = 8) => Transform(s, lines =>
    {
        string pad = new string(' ', spaces);
        for (int i = 0; i < lines.Length; i++)
        {
            if (lines[i].StartsWith('#'))
                lines[i] += pad;
        }
        return lines;
    });

    private static string TrueBlankLinesInBlock(string s) => Transform(s, lines =>
    {
        List<string> list = new List<string>();
        foreach (string l in lines)
        {
            list.Add(l);
            if (IsB64(l) && l.Length > 20)
                list.Add(""); // real empty
        }
        return list;
    });

    private static string TabsInsideBase64(string s, int chunk = 16) => MapB64(s, l =>
    {
        string p = l[2..];
        return "# " + string.Join("\t", Enumerable.Range(0, ((p.Length + chunk) - 1) / chunk).Select(i => p.Substring(i * chunk, Math.Min(chunk, p.Length - (i * chunk)))));
    });

    private static string ZeroWidthSpaceInBase64(string s) => MapB64(s, l =>
    {
        string p = l[2..];
        return "# " + string.Join("\u200B", Enumerable.Range(0, (p.Length + 14) / 15).Select(i => p.Substring(i * 15, Math.Min(15, p.Length - (i * 15)))));
    });

    private static string HashInjectedInBase64(string s) => MapB64(s, l =>
    {
        string p = l[2..];
        int at = Math.Max(1, p.Length / 2);
        return "# " + p[..at] + " ## " + p[at..];
    });

    private static string UrlSafeB64(string s) => MapB64(s, l => "# " + l[2..].Replace("+", "-", StringComparison.Ordinal).Replace("/", "_", StringComparison.Ordinal));

    private static string StripPaddingB64(string s) => MapB64(s, l => "# " + l[2..].Replace("=", "", StringComparison.Ordinal));
    private static string ExtraPaddingB64(string s) => MapB64(s, l => "# " + l[2..] + "====");

    private static string ControlWsInB64(string s) => MapB64(s, l =>
    {
        string p = l[2..];
        string vt = string.Join("\v", Enumerable.Range(0, (p.Length + 19) / 20).Select(i => p.Substring(i * 20, Math.Min(20, p.Length - (i * 20)))));
        return "# " + string.Join("\f", Enumerable.Range(0, (vt.Length + 29) / 30).Select(i => vt.Substring(i * 30, Math.Min(30, vt.Length - (i * 30)))));
    });

    private static string BomInsideFirstB64(string s)
    {
        bool done = false;
        return MapB64(s, l =>
        {
            if (!done && l.StartsWith("# ", StringComparison.Ordinal))
            {
                done = true;
                return "# \uFEFF" + l[2..];
            }
            return l;
        });
    }

    private static string NullsInB64(string s) => MapB64(s, l => "# " + string.Join("\0", l[2..].Select(c => c.ToString())));

    private static (string begin, string end, string[] b64) SplitBlock(string s)
    {
        string[] lines = s.Split(NewLineArr, StringSplitOptions.None);
        return (lines[0], lines[^1], lines.Skip(1).Take(lines.Length - 2).ToArray());
    }

    private static string Nested_BeginBegin_EndEnd(string s)
    {
        (string beg, string end, string[] b64) = SplitBlock(s);
        List<string> lines = [beg, beg];
        lines.AddRange(b64);
        lines.Add(end);
        lines.AddRange(b64);
        lines.Add(end);
        return string.Join(NewLine, lines);
    }

    private static string Interleaved_TwoBlocks(string s)
    {
        (string beg, string end, string[] b64) = SplitBlock(s);
        List<string> lines = [beg, beg];
        foreach (string l in b64)
        {
            lines.Add(l);
            lines.Add(l);
        }
        lines.Add(end);
        lines.Add(end);
        return string.Join(NewLine, lines);
    }

    private static string Crossed_PartialThenBegin(string s)
    {
        (string beg, string end, string[] b64) = SplitBlock(s);
        int cut = b64.Length / 3;
        List<string> lines = [beg];
        lines.AddRange(b64.Take(cut));
        lines.Add(beg);
        lines.AddRange(b64.Skip(cut));
        lines.Add(end);
        lines.AddRange(b64);
        lines.Add(end);
        return string.Join(NewLine, lines);
    }

    private static string EndBeforeBegin_ThenValid(string s) => EndMarker + NewLine + s;

    private static string BeginInsideB64_ThenEnd_ThenValid(string s)
    {
        (string beg, string end, string[] b64) = SplitBlock(s);
        List<string> list = [beg];
        list.AddRange(b64.Take(10));
        list.Add(beg);
        list.AddRange(b64.Skip(10));
        list.Add(end);
        return string.Join(NewLine, list) + NewLine + s;
    }

    private static string BeginEndSameLine_ThenValid(string s) => "# SIG # Begin signature block # SIG # End signature block\r\n" + s;

    private static string EndThenBegin_Inline(string s)
    {
        (string beg, string end, string[] b64) = SplitBlock(s);
        List<string> lines = [end, beg];
        lines.AddRange(b64);
        lines.Add(end);
        return string.Join(NewLine, lines);
    }

    private static string InsertAfterLastB64(string s, IEnumerable<string> extraLines)
    {
        List<string> lines = s.Split(NewLineArr, StringSplitOptions.None).ToList();
        int lastB64 = -1;

        for (int i = 0; i < lines.Count; i++)
            if (IsB64(lines[i]))
                lastB64 = i;

        if (lastB64 >= 0)
            lines.InsertRange(lastB64 + 1, extraLines);

        return string.Join(NewLine, lines);
    }

    private static string ReplaceB64Seq(string s, Func<List<string>, List<string>> reorder)
    {
        string[] lines = s.Split(NewLineArr, StringSplitOptions.None);
        List<int> idxs = new List<int>();
        List<string> b64 = new List<string>();
        for (int i = 0; i < lines.Length; i++)
        {
            if (IsB64(lines[i]))
            {
                idxs.Add(i);
                b64.Add(lines[i]);
            }
        }
        List<string> outSeq = reorder(b64);
        for (int k = 0; k < idxs.Count && k < outSeq.Count; k++)
            lines[idxs[k]] = outSeq[k];

        // if outSeq has fewer elements, drop extras; if more, insert before End marker
        if (outSeq.Count > idxs.Count)
        {
            int insertAt = Array.FindLastIndex(lines, IsMarker); // End marker index
            List<string> list = lines.ToList();
            list.InsertRange(insertAt, outSeq.Skip(idxs.Count));
            return string.Join(NewLine, list);
        }

        if (outSeq.Count < idxs.Count)
        {
            List<string> list = lines.ToList();
            foreach (int r in idxs.Skip(outSeq.Count).OrderByDescending(x => x))
                list.RemoveAt(r);
            return string.Join(NewLine, list);
        }
        return string.Join(NewLine, (IEnumerable<string>)lines);
    }

    private static string InsertB64BeforeEnd(string s)
    {
        //Remove the padding char
        s = s.Replace('=', 'y');

        List<string> lines = s.Split(NewLineArr, StringSplitOptions.None).ToList();
        int lastB64 = -1;

        for (int i = 0; i < lines.Count; i++)
            if (IsB64(lines[i]))
                lastB64 = i;

        if (lastB64 >= 0)
            lines[lastB64] += Convert.ToBase64String("tester"u8.ToArray()); // Insert a duplicate of the final legitimate base64 line just before the End marker

        return string.Join(NewLine, lines);
    }
}