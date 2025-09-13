using System.Runtime.InteropServices;
using Genbox.FastCodeSignature.Internal.MachObject.Headers;
using Genbox.FastCodeSignature.Internal.MachObject.Headers.Enums;

namespace Genbox.FastCodeSignature.Internal.MachObject;

[StructLayout(LayoutKind.Auto)]
internal readonly ref struct MachObject
{
    private static readonly byte[] LinkEditBytes = "__LINKEDIT"u8.ToArray();
    private static readonly byte[] TextBytes = "__TEXT"u8.ToArray();

    internal MachObject(ReadOnlySpan<byte> data)
    {
        int offset = 0;
        MachMagic magic = (MachMagic)ReadUInt32BigEndian(data);
        offset += 4;

        (bool le, bool is64Bit) = magic switch
        {
            MachMagic.MachMagicLE => (true, false),
            MachMagic.MachMagic64LE => (true, true),
            MachMagic.MachMagicBE => (false, false),
            MachMagic.MachMagic64BE => (false, true),
            _ => throw new NotSupportedException($"Unsupported magic: {magic}")
        };

        MachHeader = MachHeader.Read(data[offset..], le);
        offset += is64Bit ? MachHeader.StructSize64 : MachHeader.StructSize32;

        for (int i = 0; i < MachHeader.NumberOfCommands; i++)
        {
            LoadCommandHeader lcHeader = LoadCommandHeader.Read(data[offset..], le);
            int tempOffset = offset + LoadCommandHeader.StructSize;

            switch (lcHeader.Type)
            {
                case LoadCommandType.SEGMENT:

                    if (LinkEdit.Offset != 0 && Text.Offset != 0)
                        break; //We have found what we need

                    Segment seg32Header = Segment.Read32(data[tempOffset..], tempOffset, le);

                    if (seg32Header.Name.AsSpan(0, LinkEditBytes.Length).SequenceEqual(LinkEditBytes))
                        LinkEdit = seg32Header;
                    else if (seg32Header.Name.AsSpan(0, TextBytes.Length).SequenceEqual(TextBytes))
                        Text = seg32Header;

                    break;
                case LoadCommandType.SEGMENT_64:

                    if (LinkEdit.Offset != 0 && Text.Offset != 0)
                        break; //We have found what we need

                    Segment seg64Header = Segment.Read64(data[tempOffset..], tempOffset, le);

                    if (seg64Header.Name.AsSpan(0, LinkEditBytes.Length).SequenceEqual(LinkEditBytes))
                        LinkEdit = seg64Header;
                    else if (seg64Header.Name.AsSpan(0, TextBytes.Length).SequenceEqual(TextBytes))
                        Text = seg64Header;

                    break;
                case LoadCommandType.CODE_SIGNATURE:
                    CodeSignature = CodeSignatureHeader.Read(data[tempOffset..], tempOffset, le);
                    break;
            }

            //Add the size of the header to the offset so that it starts at the data for the load command
            //The size of the command also includes the header. We remove it.
            offset += (int)lcHeader.Size;
        }

        IsLittleEndian = le;
        Is64Bit = is64Bit;
    }

    internal bool IsLittleEndian { get; }
    internal bool Is64Bit { get; }
    internal MachHeader MachHeader { get; }
    internal CodeSignatureHeader CodeSignature { get; }
    internal Segment LinkEdit { get; }
    internal Segment Text { get; }
}