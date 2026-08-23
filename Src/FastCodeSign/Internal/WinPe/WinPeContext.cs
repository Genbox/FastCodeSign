using Genbox.FastCodeSign.Abstracts;
using Genbox.FastCodeSign.Misc;

namespace Genbox.FastCodeSign.Internal.WinPe;

internal sealed class WinPeContext : IContext
{
    internal required uint ChecksumOffset { get; init; }
    internal required uint SizeOfOptionalHeader { get; init; }
    internal required PeSection[] Sections { get; init; }
    internal required uint SecurityDirOffset { get; init; }
    internal required uint SecurityVirtualAddress { get; init; }
    internal required uint SecuritySize { get; init; }

    public required bool IsSigned { get; init; }

    public static WinPeContext Create(ReadOnlySpan<byte> data)
    {
        // Docs: https://upload.wikimedia.org/wikipedia/commons/1/1b/Portable_Executable_32_bit_Structure_in_SVG_fixed.svg

        if (data.Length < 64)
            throw new InvalidFileException("The file is too small to contain a valid DOS header.");

        ushort dosSignature = ReadUInt16LittleEndian(data);

        if (dosSignature != 0x5A4D) //MZ
            throw new InvalidFileException("The file has an invalid DOS signature.");

        // DOS header: Read e_lfanew, which is the pointer to the COFF header
        uint coffHeaderOffset = ReadUInt32LittleEndian(data[60..]);

        if (coffHeaderOffset > (uint)(data.Length - 4))
            throw new InvalidFileException("The file has an invalid COFF header offset.");

        // COFF header: Read the PE signature
        uint peSignature = ReadUInt32LittleEndian(data[(int)coffHeaderOffset..]);

        if (peSignature != 0x00004550) // "PE\0\0"
            throw new InvalidFileException("The file has an invalid PE signature.");

        if (coffHeaderOffset + 24 > (uint)data.Length)
            throw new InvalidFileException("The COFF header is truncated.");

        ushort numberOfSections = ReadUInt16LittleEndian(data[(int)(coffHeaderOffset + 6)..]);
        ushort sizeOfOptionalHeader = ReadUInt16LittleEndian(data[(int)(coffHeaderOffset + 20)..]);

        uint optionalHeaderOffset = coffHeaderOffset + 24;

        if (optionalHeaderOffset + sizeOfOptionalHeader > (uint)data.Length)
            throw new InvalidFileException("The optional header is truncated.");

        ushort magic = ReadUInt16LittleEndian(data[(int)optionalHeaderOffset..]);

        uint sectionTableOffset = optionalHeaderOffset + sizeOfOptionalHeader;

        if (sectionTableOffset > (uint)data.Length)
            throw new InvalidFileException("The section table offset is beyond the end of the file.");

        // Read PE sections
        List<PeSection> sections = new List<PeSection>(numberOfSections);

        for (uint i = 0; i < numberOfSections; i++)
        {
            uint sh = sectionTableOffset + (i * 40); //40 = section header size

            if (sh + 40 > (uint)data.Length)
                throw new InvalidFileException("The section table is truncated.");

            uint sizeOfRawData = ReadUInt32LittleEndian(data[((int)sh + 16)..]);
            uint pointerToRawData = ReadUInt32LittleEndian(data[((int)sh + 20)..]);

            if (sizeOfRawData > 0)
                sections.Add(new PeSection(sizeOfRawData, pointerToRawData));
        }

        if (optionalHeaderOffset + 64 > (uint)data.Length)
            throw new InvalidFileException("The optional header is truncated.");

        uint sizeOfHeaders = ReadUInt32LittleEndian(data[((int)optionalHeaderOffset + 60)..]);

        // Skip 4-byte checksum, then hash to before security directory
        uint checksumOffset = coffHeaderOffset + 88;

        // Magic values:
        // - 0x10b: 32bit
        // - 0x20b: 64bit
        // Find the offset to the security data directory (contains the authenticode certificates)
        uint dataDirOffset = (uint)(coffHeaderOffset + (magic == 0x10b ? 120 : 136));

        if (sizeOfOptionalHeader < (dataDirOffset - optionalHeaderOffset) + 8 || dataDirOffset + 8 > (uint)data.Length)
            throw new InvalidFileException("The data directory is truncated.");

        // Data Directory is a set of (PVA + Size) which is 8 bytes in total.
        uint securityDirOffset = dataDirOffset + (4 * 8); // entry #4
        uint securityVirtualAddress = ReadUInt32LittleEndian(data[(int)securityDirOffset..]);
        uint securitySize = ReadUInt32LittleEndian(data[(int)(securityDirOffset + 4)..]);

        if (securityVirtualAddress != 0 && (securityVirtualAddress > (uint)data.Length || securitySize > (uint)data.Length || securityVirtualAddress + securitySize > (uint)data.Length))
            throw new InvalidFileException("The security directory points outside the file.");

        return new WinPeContext
        {
            IsSigned = securityDirOffset > 32 && securityVirtualAddress != 0 && securitySize > 12,
            ChecksumOffset = checksumOffset,
            SizeOfOptionalHeader = sizeOfHeaders,
            Sections = sections.OrderBy(h => h.PointerToRawData).ToArray(),
            SecurityDirOffset = securityDirOffset,
            SecurityVirtualAddress = securityVirtualAddress,
            SecuritySize = securitySize
        };
    }
}