using Genbox.FastCodeSign.Abstracts;
using Genbox.FastCodeSign.Internal.MachObject.Headers;
using Genbox.FastCodeSign.Internal.MachObject.Headers.Enums;

namespace Genbox.FastCodeSign.Internal.MachObject;

internal class MachOContext : IContext
{
    private static readonly byte[] LinkEditBytes = "__LINKEDIT"u8.ToArray();
    private static readonly byte[] TextBytes = "__TEXT"u8.ToArray();

    internal required bool IsLittleEndian { get; init; }
    internal required bool Is64Bit { get; init; }
    internal required MachHeader MachHeader { get; init; }
    internal required CodeSignatureHeader? CodeSignature { get; init; }
    internal required Segment LinkEdit { get; init; }
    internal required Segment Text { get; init; }

    public required bool IsSigned { get; init; }

    public static MachOContext Create(ReadOnlySpan<byte> data)
    {
        //Note: I could be more strict here, but it is not well-defined what constitutes a "minimal mach object".
        if (data.Length < 4)
            throw new InvalidDataException("The Mach Object header is truncated.");

        MachMagic magic = (MachMagic)ReadUInt32BigEndian(data);

        (bool le, bool is64Bit) = magic switch
        {
            MachMagic.MachMagicLE => (true, false),
            MachMagic.MachMagic64LE => (true, true),
            MachMagic.MachMagicBE => (false, false),
            MachMagic.MachMagic64BE => (false, true),
            _ => throw new NotSupportedException($"Unsupported magic: {magic}")
        };

        int offset = 4;

        if (data.Length < offset + (is64Bit ? MachHeader.StructSize64 : MachHeader.StructSize32))
            throw new InvalidDataException("The Mach Object header is truncated.");

        MachHeader machHeader = MachHeader.Read(data[offset..], le);
        offset += is64Bit ? MachHeader.StructSize64 : MachHeader.StructSize32;

        if (machHeader.SizeOfCommands > data.Length - offset)
            throw new InvalidDataException("The Mach Object load commands are truncated.");

        int commandEnd = offset + (int)machHeader.SizeOfCommands;

        Segment? linkEdit = null;
        Segment? text = null;
        CodeSignatureHeader? codeSignature = null;

        for (int i = 0; i < machHeader.NumberOfCommands; i++)
        {
            if (offset + LoadCommandHeader.StructSize > commandEnd)
                throw new InvalidDataException("The Mach Object load command header is truncated.");

            LoadCommandHeader lcHeader = LoadCommandHeader.Read(data[offset..], le);
            if (lcHeader.Size < LoadCommandHeader.StructSize || lcHeader.Size > commandEnd - offset)
                throw new InvalidDataException("The Mach Object load command size is invalid.");

            int tempOffset = offset + LoadCommandHeader.StructSize;
            int nextOffset = offset + (int)lcHeader.Size;

            switch (lcHeader.Type)
            {
                case LoadCommandType.SEGMENT:

                    if (lcHeader.Size < 56)
                        throw new InvalidDataException("The Mach Object segment load command is truncated.");

                    if (linkEdit != null && text != null)
                        break; //We have found what we need

                    Segment seg32Header = Segment.Read32(data[tempOffset..], tempOffset, le);

                    if (seg32Header.Name.AsSpan(0, LinkEditBytes.Length).SequenceEqual(LinkEditBytes))
                        linkEdit = seg32Header;
                    else if (seg32Header.Name.AsSpan(0, TextBytes.Length).SequenceEqual(TextBytes))
                        text = seg32Header;

                    break;
                case LoadCommandType.SEGMENT_64:

                    if (lcHeader.Size < 72)
                        throw new InvalidDataException("The Mach Object segment load command is truncated.");

                    if (linkEdit != null && text != null)
                        break; //We have found what we need

                    Segment seg64Header = Segment.Read64(data[tempOffset..], tempOffset, le);

                    if (seg64Header.Name.AsSpan(0, LinkEditBytes.Length).SequenceEqual(LinkEditBytes))
                        linkEdit = seg64Header;
                    else if (seg64Header.Name.AsSpan(0, TextBytes.Length).SequenceEqual(TextBytes))
                        text = seg64Header;

                    break;
                case LoadCommandType.CODE_SIGNATURE:
                    if (lcHeader.Size < LoadCommandHeader.StructSize + CodeSignatureHeader.StructSize)
                        throw new InvalidDataException("The Mach Object code signature load command is truncated.");

                    codeSignature = CodeSignatureHeader.Read(data[tempOffset..], tempOffset, le);
                    break;
            }

            //Add the size of the header to the offset so that it starts at the data for the load command
            //The size of the command also includes the header. We remove it.
            offset = nextOffset;
        }

        if (linkEdit == null)
            throw new InvalidOperationException("The Mach Object file does not contain a __LINKEDIT section.");

        if (text == null)
            throw new InvalidOperationException("The Mach Object file does not contain a __TEXT section.");

        if (codeSignature != null)
        {
            ulong sigEnd = (ulong)codeSignature.DataOffset + codeSignature.DataSize;
            if (codeSignature.DataOffset == 0 || codeSignature.DataSize == 0 || sigEnd > (ulong)data.Length)
                throw new InvalidDataException("The code signature load command points outside the file.");
        }

        return new MachOContext
        {
            IsSigned = codeSignature != null && codeSignature.DataOffset != 0 && codeSignature.DataSize != 0,
            IsLittleEndian = le,
            Is64Bit = is64Bit,
            MachHeader = machHeader,
            CodeSignature = codeSignature,
            LinkEdit = linkEdit,
            Text = text
        };
    }
}