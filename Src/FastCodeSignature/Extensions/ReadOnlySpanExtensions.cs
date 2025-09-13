using Genbox.FastCodeSignature.Internal.MachObject.Headers.Enums;

namespace Genbox.FastCodeSignature.Extensions;

public static class ReadOnlySpanExtensions
{
    /// <summary>
    /// Parse a Fat Mach Object file into thin object files.
    /// </summary>
    /// <param name="data">The fat mach object file data</param>
    /// <returns>Offset and sizes of each thin object file. In case the input is a thin object, it will return a single offset to the beginning of the file.</returns>
    /// <exception cref="InvalidDataException"></exception>
    public static (int offset, int size)[] GetThinMachObjects(this ReadOnlySpan<byte> data)
    {
        MachMagic magic = (MachMagic)ReadUInt32BigEndian(data);

        bool isFat32 = magic is MachMagic.FatMagicBE or MachMagic.FatMagicLE;
        bool isFat64 = magic is MachMagic.FatMagic64BE or MachMagic.FatMagic64LE;

        //Not a fat
        if (!isFat32 && !isFat64)
            return [(0, data.Length)];

        uint fatCount = ReadUInt32BigEndian(data[4..]);

        if (fatCount == 0)
            throw new InvalidDataException("Empty fat file.");

        (int, int)[] thins = new (int, int)[fatCount];

        int off = 8;

        if (isFat64)
        {
            for (uint i = 0; i < fatCount; i++, off += 32)
            {
                // fat_arch_64: 32 bytes each; first at offset 8
                if (off + 32 > data.Length)
                    throw new InvalidDataException("Truncated fat_arch_64");

                ulong sOff = ReadUInt64BigEndian(data[16..]);
                ulong sSize = ReadUInt64BigEndian(data[24..]);
                thins[i] = (checked((int)sOff), checked((int)sSize));
            }
        }
        else
        {
            for (uint i = 0; i < fatCount; i++, off += 20)
            {
                // fat_arch: 20 bytes each; first at offset 8
                if (off + 20 > data.Length)
                    throw new InvalidDataException("Truncated fat_arch");

                uint sOff = ReadUInt32BigEndian(data[16..]);
                uint sSize = ReadUInt32BigEndian(data[20..]);
                thins[i] = (checked((int)sOff), checked((int)sSize));
            }
        }
        return thins;
    }
}