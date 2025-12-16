using Genbox.FastCodeSign.Enums;
using Genbox.FastCodeSign.Internal.MachObject.Headers.Enums;
using Genbox.FastCodeSign.Models;
using static Genbox.FastCodeSign.Internal.MachObject.MachBinaryPrimitives;

namespace Genbox.FastCodeSign.Helpers;

public static class MachObjectHelper
{
    /// <summary>
    /// Parse a Fat Mach Object file into thin object files offsets and sizes. If there is no fat header, it returns an object that spans the entire file.
    /// </summary>
    /// <param name="data">The fat mach object file data</param>
    /// <returns>Offset and sizes of each thin object file</returns>
    /// <exception cref="InvalidDataException">Thrown on invalid files</exception>
    public static MachObject[] GetMachObjects(ReadOnlySpan<byte> data)
    {
        if (data.Length < 12)
            throw new InvalidDataException("Truncated mach object header");

        MachMagic magic = (MachMagic)ReadUInt32BigEndian(data);

        bool is64Bit;
        bool le;

        switch (magic)
        {
            case MachMagic.MachMagicBE:
            case MachMagic.MachMagic64BE:
                return CreateThinObject(data, false);
            case MachMagic.MachMagicLE:
            case MachMagic.MachMagic64LE:
                return CreateThinObject(data, true);
            case MachMagic.FatMagicBE:
                is64Bit = false;
                le = false;
                break;
            case MachMagic.FatMagicLE:
                is64Bit = false;
                le = true;
                break;
            case MachMagic.FatMagic64BE:
                is64Bit = true;
                le = false;
                break;
            case MachMagic.FatMagic64LE:
                is64Bit = true;
                le = true;
                break;
            default:
                throw new InvalidOperationException("The file is not a valid mach object");
        }

        //See https://github.com/apple-oss-distributions/xnu/blob/e3723e1f17661b24996789d8afc084c0c3303b26/EXTERNAL_HEADERS/mach-o/fat.h#L51

        uint fatCount = ReadU32(data[4..], le);

        if (fatCount == 0)
            throw new InvalidDataException("Empty fat file");

        MachObject[] objs = new MachObject[fatCount];

        int offset = 8;
        int archSize = is64Bit ? 32 : 20;

        for (uint i = 0; i < fatCount; i++)
        {
            if (offset + archSize > data.Length)
                throw new InvalidDataException("Truncated fat entry");

            uint cpuType = ReadU32(data[offset..], le);
            offset += 4;

            uint cpuSubType = ReadU32(data[offset..], le);
            offset += 4;

            ulong sOffset, sSize;
            uint sAlign;

            if (is64Bit)
            {
                sOffset = ReadU64(data[offset..], le);
                offset += 8;
                sSize = ReadU64(data[offset..], le);
                offset += 8;
                sAlign = ReadU32(data[offset..], le);
                offset += 4;

                offset += 4; //This is the reserved field
            }
            else
            {
                sOffset = ReadU32(data[offset..], le);
                offset += 4;
                sSize = ReadU32(data[offset..], le);
                offset += 4;
                sAlign = ReadU32(data[offset..], le);
                offset += 4;
            }

            CpuType cpuTypeEnum = (CpuType)cpuType;
            Enum cpuSubTypeEnum = CpuSubTypeToEnum(cpuTypeEnum, cpuSubType);

            objs[i] = new MachObject(cpuTypeEnum, cpuSubTypeEnum, sOffset, sSize, sAlign);
        }

        return objs;

        static MachObject[] CreateThinObject(ReadOnlySpan<byte> data, bool le)
        {
            uint cpuType = ReadU32(data[4..], le);
            uint cpuSubType = ReadU32(data[8..], le);

            CpuType cpuTypeEnum = (CpuType)cpuType;
            Enum cpuSubTypeEnum = CpuSubTypeToEnum(cpuTypeEnum, cpuSubType);

            return [new MachObject(cpuTypeEnum, cpuSubTypeEnum, 0, (ulong)data.Length, 0)];
        }
    }

    private static Enum CpuSubTypeToEnum(CpuType cpuTypeEnum, uint cpuSubType) => cpuTypeEnum switch
    {
        CpuType.X86 or CpuType.X86_64 => (X8664CpuSubType)cpuSubType,
        CpuType.ARM => (ArmCpuSubType)cpuSubType,
        CpuType.ARM64 or CpuType.ARM64_32 => (Arm64CpuSubType)cpuSubType,
        _ => CpuSubType.Any
    };
}