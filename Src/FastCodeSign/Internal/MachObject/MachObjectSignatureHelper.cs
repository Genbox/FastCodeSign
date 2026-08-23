using Genbox.FastCodeSign.Abstracts;
using Genbox.FastCodeSign.Allocations;
using Genbox.FastCodeSign.Handlers;
using Genbox.FastCodeSign.Internal.MachObject.Headers.Enums;
using Genbox.FastCodeSign.Models;
using static Genbox.FastCodeSign.Internal.MachObject.MachBinaryPrimitives;
using MachObjectModel = Genbox.FastCodeSign.Models.MachObject;

namespace Genbox.FastCodeSign.Internal.MachObject;

internal static class MachObjectSignatureHelper
{
    public static void WriteSignatures(IAllocation allocation, MachObjectModel[] machObjects, Signature[] signatures)
    {
        if (machObjects.Length != signatures.Length)
            throw new InvalidOperationException("The number of Mach-O signatures does not match the number of slices.");

        Span<byte> data = allocation.GetSpan();
        MachMagic magic = (MachMagic)ReadUInt32BigEndian(data);
        if (magic is not (MachMagic.FatMagicBE or MachMagic.FatMagicLE or MachMagic.FatMagic64BE or MachMagic.FatMagic64LE))
        {
            IFormatHandler handler = new MachObjectFormatHandler();
            handler.WriteSignature(handler.GetContext(data), allocation, signatures[0]);
            return;
        }

        bool is64Bit = magic is MachMagic.FatMagic64BE or MachMagic.FatMagic64LE;
        bool littleEndian = magic is MachMagic.FatMagicLE or MachMagic.FatMagic64LE;
        int archHeaderSize = is64Bit ? 32 : 20;
        int headerSize = checked(8 + (machObjects.Length * archHeaderSize));
        MemoryAllocation[] signedSlices = new MemoryAllocation[machObjects.Length];
        IFormatHandler sliceHandler = new MachObjectFormatHandler();

        ulong offset = (ulong)headerSize;
        for (int i = 0; i < machObjects.Length; i++)
        {
            MemoryAllocation sliceAllocation = new MemoryAllocation(machObjects[i].GetSpan(data).ToArray());
            sliceHandler.WriteSignature(sliceHandler.GetContext(sliceAllocation.GetSpan()), sliceAllocation, signatures[i]);
            signedSlices[i] = sliceAllocation;
            offset = Align(offset, 1UL << checked((int)machObjects[i].Align));
            offset += (uint)sliceAllocation.GetSpan().Length;
        }

        byte[] rebuilt = new byte[checked((int)offset)];
        data[..8].CopyTo(rebuilt);
        WriteU32(rebuilt.AsSpan(4), (uint)machObjects.Length, littleEndian);

        offset = (ulong)headerSize;
        for (int i = 0; i < machObjects.Length; i++)
        {
            offset = Align(offset, 1UL << checked((int)machObjects[i].Align));
            Span<byte> signedSlice = signedSlices[i].GetSpan();
            signedSlice.CopyTo(rebuilt.AsSpan(checked((int)offset)));

            int archOffset = 8 + (i * archHeaderSize);
            WriteU32(rebuilt.AsSpan(archOffset), (uint)machObjects[i].CpuType, littleEndian);
            WriteU32(rebuilt.AsSpan(archOffset + 4), Convert.ToUInt32(machObjects[i].CpuSubType), littleEndian);
            if (is64Bit)
            {
                WriteU64(rebuilt.AsSpan(archOffset + 8), offset, littleEndian);
                WriteU64(rebuilt.AsSpan(archOffset + 16), (ulong)signedSlice.Length, littleEndian);
                WriteU32(rebuilt.AsSpan(archOffset + 24), machObjects[i].Align, littleEndian);
            }
            else
            {
                WriteU32(rebuilt.AsSpan(archOffset + 8), checked((uint)offset), littleEndian);
                WriteU32(rebuilt.AsSpan(archOffset + 12), (uint)signedSlice.Length, littleEndian);
                WriteU32(rebuilt.AsSpan(archOffset + 16), machObjects[i].Align, littleEndian);
            }

            offset += (uint)signedSlice.Length;
        }

        allocation.SetLength(checked((uint)rebuilt.Length));
        rebuilt.CopyTo(allocation.GetSpan());
    }

    public static void RemoveSignatures(IAllocation allocation, MachObjectModel[] machObjects)
    {
        Span<byte> data = allocation.GetSpan();
        MemoryAllocation[] unsignedSlices = new MemoryAllocation[machObjects.Length];
        IFormatHandler sliceHandler = new MachObjectFormatHandler();

        for (int i = 0; i < machObjects.Length; i++)
        {
            MemoryAllocation sliceAllocation = new MemoryAllocation(machObjects[i].GetSpan(data).ToArray());
            IContext context = sliceHandler.GetContext(sliceAllocation.GetSpan());
            if (context.IsSigned)
                sliceHandler.RemoveSignature(context, sliceAllocation);
            unsignedSlices[i] = sliceAllocation;
        }

        Rebuild(allocation, machObjects, unsignedSlices);
    }

    private static void Rebuild(IAllocation allocation, MachObjectModel[] machObjects, MemoryAllocation[] slices)
    {
        Span<byte> data = allocation.GetSpan();
        MachMagic magic = (MachMagic)ReadUInt32BigEndian(data);
        bool is64Bit = magic is MachMagic.FatMagic64BE or MachMagic.FatMagic64LE;
        bool littleEndian = magic is MachMagic.FatMagicLE or MachMagic.FatMagic64LE;
        int archHeaderSize = is64Bit ? 32 : 20;
        int headerSize = checked(8 + (machObjects.Length * archHeaderSize));
        ulong offset = (ulong)headerSize;
        for (int i = 0; i < slices.Length; i++)
        {
            offset = Align(offset, 1UL << checked((int)machObjects[i].Align));
            offset += (uint)slices[i].GetSpan().Length;
        }

        byte[] rebuilt = new byte[checked((int)offset)];
        data[..8].CopyTo(rebuilt);
        WriteU32(rebuilt.AsSpan(4), (uint)machObjects.Length, littleEndian);
        offset = (ulong)headerSize;
        for (int i = 0; i < slices.Length; i++)
        {
            offset = Align(offset, 1UL << checked((int)machObjects[i].Align));
            Span<byte> slice = slices[i].GetSpan();
            slice.CopyTo(rebuilt.AsSpan(checked((int)offset)));
            int archOffset = 8 + (i * archHeaderSize);
            WriteU32(rebuilt.AsSpan(archOffset), (uint)machObjects[i].CpuType, littleEndian);
            WriteU32(rebuilt.AsSpan(archOffset + 4), Convert.ToUInt32(machObjects[i].CpuSubType), littleEndian);
            if (is64Bit)
            {
                WriteU64(rebuilt.AsSpan(archOffset + 8), offset, littleEndian);
                WriteU64(rebuilt.AsSpan(archOffset + 16), (ulong)slice.Length, littleEndian);
                WriteU32(rebuilt.AsSpan(archOffset + 24), machObjects[i].Align, littleEndian);
            }
            else
            {
                WriteU32(rebuilt.AsSpan(archOffset + 8), checked((uint)offset), littleEndian);
                WriteU32(rebuilt.AsSpan(archOffset + 12), (uint)slice.Length, littleEndian);
                WriteU32(rebuilt.AsSpan(archOffset + 16), machObjects[i].Align, littleEndian);
            }
            offset += (uint)slice.Length;
        }

        allocation.SetLength(checked((uint)rebuilt.Length));
        rebuilt.CopyTo(allocation.GetSpan());
    }
}