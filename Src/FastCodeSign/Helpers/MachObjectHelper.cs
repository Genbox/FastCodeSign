using Genbox.FastCodeSign.Internal.MachObject.Headers.Enums;
using Genbox.FastCodeSign.Models;

namespace Genbox.FastCodeSign.Helpers;

public static class MachObjectHelper
{
    /// <summary>
    /// Parse a Fat Mach Object file into thin object files offsets and sizes.
    /// </summary>
    /// <param name="data">The fat mach object file data</param>
    /// <returns>Offset and sizes of each thin object file</returns>
    /// <exception cref="InvalidDataException">Thrown on invalid files</exception>
    public static FatObject[] GetThinMachObjects(ReadOnlySpan<byte> data)
    {
        if (data.Length < 8)
            throw new InvalidDataException("Truncated Mach-O / FAT header.");

        MachMagic magic = (MachMagic)ReadUInt32BigEndian(data);

        bool is64Bit;

        switch (magic)
        {
            case MachMagic.MachMagicBE:
            case MachMagic.MachMagicLE:
            case MachMagic.MachMagic64BE:
            case MachMagic.MachMagic64LE:
                //The file is already a thin object.
                return [];
            case MachMagic.FatMagicBE:
            case MachMagic.FatMagicLE:
                is64Bit = false;
                break;
            case MachMagic.FatMagic64BE:
            case MachMagic.FatMagic64LE:
                is64Bit = true;
                break;
            default:
                throw new InvalidOperationException("The file is not a valid mach object");
        }

        //See https://github.com/apple-oss-distributions/xnu/blob/e3723e1f17661b24996789d8afc084c0c3303b26/EXTERNAL_HEADERS/mach-o/fat.h#L51

        uint fatCount = ReadUInt32BigEndian(data[4..]);

        if (fatCount == 0)
            throw new InvalidDataException("Empty fat file.");

        FatObject[] thins = new FatObject[fatCount];

        int offset = 8;
        int archSize = is64Bit ? 32 : 20;

        for (uint i = 0; i < fatCount; i++)
        {
            if (offset + archSize > data.Length)
                throw new InvalidDataException("Truncated FAT arch entry.");

            uint cpuType = ReadUInt32BigEndian(data.Slice(offset, 4));
            offset += 4;

            uint cpuSubType = ReadUInt32BigEndian(data.Slice(offset, 4));
            offset += 4;

            ulong sOffset, sSize;
            uint sAlign;

            if (is64Bit)
            {
                sOffset = ReadUInt64BigEndian(data.Slice(offset, 8));
                offset += 8;
                sSize = ReadUInt64BigEndian(data.Slice(offset, 8));
                offset += 8;
                sAlign = ReadUInt32BigEndian(data.Slice(offset, 4));
                offset += 4;

                offset += 4; //This is the reserved field
            }
            else
            {
                sOffset = ReadUInt32BigEndian(data.Slice(offset, 4));
                offset += 4;
                sSize = ReadUInt32BigEndian(data.Slice(offset, 4));
                offset += 4;
                sAlign = ReadUInt32BigEndian(data.Slice(offset, 4));
                offset += 4;
            }

            thins[i] = new FatObject(cpuType, cpuSubType, sOffset, sSize, sAlign);
        }

        return thins;
    }
}