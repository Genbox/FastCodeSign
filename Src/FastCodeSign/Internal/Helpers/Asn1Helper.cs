namespace Genbox.FastCodeSign.Internal.Helpers;

internal static class Asn1Helper
{
    internal static byte[]? GetNullableBytes(ReadOnlySpan<byte> span)
    {
        if (span.Length == 2 && span[0] == 5 && span[1] == 0)
            return null;

        return span.ToArray();
    }

    internal static int GetAsn1SequenceEncodedLength(ReadOnlySpan<byte> data)
    {
        if (data.Length < 2 || data[0] != 0x30) // SEQUENCE
            throw new InvalidDataException("The ASN.1 structure is invalid.");

        byte lengthByte = data[1];

        if (lengthByte < 0x80)
        {
            int total = 2 + lengthByte;
            if (total > data.Length)
                throw new InvalidDataException("The ASN.1 structure is invalid.");

            return total;
        }

        if (lengthByte == 0x80)
            throw new InvalidDataException("Indefinite-length ASN.1 encoding is not supported.");

        int lengthOctets = lengthByte & 0x7F;
        if ((uint)lengthOctets > 4u || data.Length < 2 + lengthOctets)
            throw new InvalidDataException("The ASN.1 structure is invalid.");

        uint contentLength = 0;
        for (int i = 0; i < lengthOctets; i++)
            contentLength = (contentLength << 8) | data[2 + i];

        int headerLength = 2 + lengthOctets;
        uint totalLength = (uint)headerLength + contentLength;

        if (totalLength > (uint)data.Length)
            throw new InvalidDataException("The ASN.1 structure is invalid.");

        return (int)totalLength;
    }
}