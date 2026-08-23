using System.Buffers.Binary;
using System.Text;
using Genbox.FastCodeSign.Abstracts;
using Genbox.FastCodeSign.Enums;
using Genbox.FastCodeSign.Handlers;
using Genbox.FastCodeSign.Helpers;
using Genbox.FastCodeSign.MachObjects;

namespace Genbox.FastCodeSign.Tests;

public class MachObjectSecurityTests
{
    [Fact]
    private void HugeFatArchCountThrowsBeforeAllocation()
    {
        byte[] data = new byte[8];
        BinaryPrimitives.WriteUInt32BigEndian(data, 0xcafebabe);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(4), uint.MaxValue);

        Assert.Throws<InvalidDataException>(() => MachObjectHelper.GetMachObjects(data));
    }

    [Fact]
    private void I386SubtypeUsesI386Enum()
    {
        byte[] data = new byte[28];
        BinaryPrimitives.WriteUInt32BigEndian(data, 0xcafebabe);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(8), (uint)CpuType.X86);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(12), (uint)I386CpuSubType.I386);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(16), 28);

        Assert.Equal(I386CpuSubType.I386, Assert.Single(MachObjectHelper.GetMachObjects(data)).CpuSubType);
    }

    [Fact]
    private void AnchorHashWritesCertificateIndex()
    {
        Expr expression = Expr.AnchorHash(-1, [1, 2, 3]);
        byte[] buffer = new byte[expression.Size];

        expression.Write(buffer);

        Assert.Equal(-1, BinaryPrimitives.ReadInt32BigEndian(buffer.AsSpan(4)));
    }

    [Fact]
    private void RemovalRejectsNonTailSignatureWithoutMutatingData()
    {
        byte[] data = CreateThinMachO(true, 240, 8, 248);
        byte[] original = data.ToArray();
        IFormatHandler handler = new MachObjectFormatHandler();
        IContext context = handler.GetContext(data);

        Assert.Throws<InvalidDataException>(() => handler.RemoveSignature(context, data));
        Assert.Equal(original, data);
    }

    [Fact]
    private void PartialFatSignatureExtractionThrowsInvalidDataException()
    {
        byte[] data = new byte[560];
        BinaryPrimitives.WriteUInt32BigEndian(data, 0xcafebabe);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(4), 2);
        WriteFatArch(data, 8, 48);
        WriteFatArch(data, 28, 304);
        CreateThinMachO(true, 240, 16, 256).CopyTo(data.AsSpan(48));
        CreateThinMachO(false, 0, 0, 256).CopyTo(data.AsSpan(304));
        IFormatHandler handler = new FatMachObjectFormatHandler();
        IContext context = handler.GetContext(data);

        Assert.Throws<InvalidDataException>(() => handler.ExtractSignature(context, data));
    }

    private static void WriteFatArch(Span<byte> data, int offset, uint sliceOffset)
    {
        BinaryPrimitives.WriteUInt32BigEndian(data[offset..], (uint)CpuType.X86_64);
        BinaryPrimitives.WriteUInt32BigEndian(data[(offset + 4)..], 3);
        BinaryPrimitives.WriteUInt32BigEndian(data[(offset + 8)..], sliceOffset);
        BinaryPrimitives.WriteUInt32BigEndian(data[(offset + 12)..], 256);
    }

    private static byte[] CreateThinMachO(bool signed, uint signatureOffset, uint signatureSize, ulong linkEditSize)
    {
        byte[] data = new byte[256];
        BinaryPrimitives.WriteUInt32BigEndian(data, 0xcffaedfe);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(16), signed ? 3U : 2U);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(20), signed ? 160U : 144U);
        WriteSegment(data, 32, "__TEXT", 0, 256);
        WriteSegment(data, 104, "__LINKEDIT", 0, linkEditSize);

        if (signed)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(176), 0x1d);
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(180), 16);
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(184), signatureOffset);
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(188), signatureSize);
        }

        return data;
    }

    private static void WriteSegment(Span<byte> data, int offset, string name, ulong fileOffset, ulong fileSize)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(data[offset..], 0x19);
        BinaryPrimitives.WriteUInt32LittleEndian(data[(offset + 4)..], 72);
        Encoding.ASCII.GetBytes(name).CopyTo(data[(offset + 8)..]);
        BinaryPrimitives.WriteUInt64LittleEndian(data[(offset + 40)..], fileOffset);
        BinaryPrimitives.WriteUInt64LittleEndian(data[(offset + 48)..], fileSize);
    }
}