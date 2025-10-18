using System.Runtime.InteropServices;
using Genbox.FastCodeSign.Internal.MachObject.Headers.Enums;

namespace Genbox.FastCodeSign.Internal.MachObject.Headers;

// https://github.com/apple-oss-distributions/xnu/blob/e3723e1f17661b24996789d8afc084c0c3303b26/osfmk/kern/cs_blobs.h#L212
[StructLayout(LayoutKind.Sequential)]
internal readonly record struct CodeDirectoryHeader
{
    public const int StructSize = 44;

    public required CsMagic Magic { get; init; } // magic number (CSMAGIC_CODEDIRECTORY)
    public required uint Length { get; init; } // total length of CodeDirectory blob
    public required Supports Version { get; init; } // compatibility version
    public required CdFlags Flags { get; init; } // setup and mode flags
    public required uint HashOffset { get; init; } // offset of hash slot element at index zero
    public required uint IdentOffset { get; init; } // offset of identifier string
    public required uint nSpecialSlots { get; init; } // number of special hash slots
    public required uint nCodeSlots { get; init; } // number of ordinary (code) hash slots
    public required uint CodeLimit { get; init; } // limit to main image signature range
    public required byte HashSize { get; init; } // size of each hash in bytes
    public required byte HashType { get; init; } // type of hash (cdHashType* constants)
    public required byte Platform { get; init; } // platform identifier; zero if not platform binary
    public required byte PageSize { get; init; } // log2(page size in bytes); 0 => infinite
    public required uint Spare2 { get; init; } // unused (must be zero)

    public void Write(Span<byte> data)
    {
        WriteUInt32BigEndian(data, (uint)Magic);
        WriteUInt32BigEndian(data[4..], Length);
        WriteInt32BigEndian(data[8..], (int)Version);
        WriteUInt32BigEndian(data[12..], (uint)Flags);
        WriteUInt32BigEndian(data[16..], HashOffset);
        WriteUInt32BigEndian(data[20..], IdentOffset);
        WriteUInt32BigEndian(data[24..], nSpecialSlots);
        WriteUInt32BigEndian(data[28..], nCodeSlots);
        WriteUInt32BigEndian(data[32..], CodeLimit);
        data[36] = HashSize;
        data[37] = HashType;
        data[38] = Platform;
        data[39] = PageSize;
        WriteUInt32BigEndian(data[40..], Spare2);
    }
}