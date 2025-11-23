using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using Genbox.FastCodeSign.Abstracts;
using Genbox.FastCodeSign.Handlers;
using Genbox.FastCodeSign.Helpers;
using Genbox.FastCodeSign.Models;
using Genbox.FastCodeSign.Tests.Code;

namespace Genbox.FastCodeSign.Tests;

public class EdgeCases
{
    [Fact]
    private void DiscordFailedValidationTest()
    {
        // During development of app bundle handling I came across a signed assembly that failed validation.
        // This test replicates the issue. Note that codesign on Mac only checks the part of the FAT assembly that pertains to the platform you run on.

        string fullPath = Path.Combine(Constants.FilesDir, "Misc/Discord-failed-validation.dat");

        // It is ia FAT file, so we need to slice it.
        Span<byte> span = File.ReadAllBytes(fullPath);
        MachObject[] objs = MachObjectHelper.GetMachObjects(span);

        MachObject obj = objs.First();

        Span<byte> subSpan = obj.GetSpan(span);

        IFormatHandler handler = new MachObjectFormatHandler();
        var context = handler.GetContext(subSpan);

        ReadOnlySpan<byte> sig = handler.ExtractSignature(context, subSpan);

        SignedCms cms = new SignedCms();
        cms.Decode(sig);

        // CDHash obtained via `codesign -dvvvvv Discord.app`

        Assert.True(handler.ExtractHashFromSignedCms(cms, out byte[]? digest, out HashAlgorithmName hashAlgo));
        Assert.Equal("01f13e7c7d9f84b9a1bd4b26cae6be489b8d9867e7394f27a75ab2b05bc3377a", Convert.ToHexStringLower(digest));

        byte[] hash = handler.ComputeHash(context, subSpan, hashAlgo);
        Assert.Equal("01f13e7c7d9f84b9a1bd4b26cae6be489b8d9867e7394f27a75ab2b05bc3377a", Convert.ToHexStringLower(hash));
    }
}