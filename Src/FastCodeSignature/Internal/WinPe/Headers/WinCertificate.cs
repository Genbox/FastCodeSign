using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Genbox.FastCodeSignature.Internal.WinPe.Headers;

[DebuggerDisplay("Length: {Length}, Revision: {Revision}, CertificateType: {CertificateType}")]
[StructLayout(LayoutKind.Sequential)]
internal struct WinCertificate
{
    internal const byte StructSize = 8;

    internal uint Length { get; init; }
    internal ushort Revision { get; init; }
    internal ushort CertificateType { get; init; }

    internal static WinCertificate Read(ReadOnlySpan<byte> data)
    {
        if (BitConverter.IsLittleEndian)
            return MemoryMarshal.Read<WinCertificate>(data);

        return new WinCertificate
        {
            Length = ReadUInt32LittleEndian(data),
            Revision = ReadUInt16LittleEndian(data[4..]),
            CertificateType = ReadUInt16LittleEndian(data[6..])
        };
    }

    internal void Write(Span<byte> data)
    {
        if (BitConverter.IsLittleEndian)
            MemoryMarshal.Write(data, this);

        WriteUInt32LittleEndian(data, Length);
        WriteUInt16LittleEndian(data[4..], Revision);
        WriteUInt16LittleEndian(data[6..], CertificateType);
    }
}