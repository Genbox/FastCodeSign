using System.Buffers;
using System.Globalization;
using System.Text;
using System.Xml;

namespace Genbox.FastCodeSign.Internal.MachObject;

internal static class PListSerializer
{
    // See https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/PropertyLists/AboutPropertyLists/AboutPropertyLists.html

    // This is a simple property list serializer with certain limitations:
    // - Only support the data types needed for code signatures
    // - Only support limited types within arrays

    internal static void Serialize(Dictionary<string, object> dict, Stream stream)
    {
        using XmlWriter writer = XmlWriter.Create(stream, new XmlWriterSettings
        {
            Indent = true,
            IndentChars = "  ",
            Encoding = new UTF8Encoding(false)
        });

        writer.WriteStartDocument(); // <?xml version="1.0" encoding="UTF-8"?>
        writer.WriteDocType(
            name: "plist",
            pubid: "-//Apple//DTD PLIST 1.0//EN",
            sysid: "http://www.apple.com/DTDs/PropertyList-1.0.dtd",
            subset: null
        );

        writer.WriteStartElement("plist");
        writer.WriteAttributeString("version", "1.0");

        WriteDictionary(writer, dict);

        writer.WriteEndElement(); // </plist>
        writer.WriteEndDocument();
    }

    internal static unsafe Dictionary<string, object> Deserialize(ReadOnlySpan<byte> buffer)
    {
        // There is no span API for XmlReader, so we UnmanagedMemoryStream to avoid copying the buffer
        fixed (byte* p = buffer)
        {
            using UnmanagedMemoryStream ms = new UnmanagedMemoryStream(p, buffer.Length);
            using XmlReader reader = XmlReader.Create(ms, new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Ignore, // don't fetch Apple DTD
                XmlResolver = null,
                IgnoreComments = true,
                IgnoreProcessingInstructions = true,
                IgnoreWhitespace = true
            });

            reader.MoveToContent();
            reader.ReadStartElement("plist");

            Dictionary<string, object> root = ReadDict(reader);

            reader.ReadEndElement(); // </plist>
            return root;
        }
    }

    private static object ReadValue(XmlReader reader)
    {
        switch (reader.LocalName)
        {
            case "string":
                return reader.ReadElementContentAsString();

            case "true":
                reader.ReadStartElement("true");
                return true;

            case "false":
                reader.ReadStartElement("false");
                return false;

            case "array":
                return ReadArray(reader);

            case "data":
                return ReadData(reader);

            case "dict":
                return ReadDict(reader);

            case "real":
                // XML plist real → IEEE-754; parse as double
                // Use XmlConvert for predictable, culture-invariant parsing.
                return XmlConvert.ToDouble(reader.ReadElementContentAsString("real", ""));

            default:
                throw new InvalidDataException($"Unsupported plist value element: <{reader.LocalName}>.");
        }
    }

    private static Dictionary<string, object> ReadDict(XmlReader reader)
    {
        reader.ReadStartElement("dict");

        Dictionary<string, object> dict = new Dictionary<string, object>(StringComparer.Ordinal);

        // Dict is a sequence of key/value pairs
        while (!(reader.NodeType == XmlNodeType.EndElement && reader.LocalName == "dict"))
        {
            if (reader.LocalName != "key")
                throw new InvalidDataException("Invalid XML: Key was not found");

            string key = reader.ReadElementContentAsString();

            if (reader.NodeType != XmlNodeType.Element)
                throw new InvalidDataException("Invalid XML: Value element was not found");

            dict[key] = ReadValue(reader);
        }

        reader.ReadEndElement(); // </dict>
        return dict;
    }

    private static byte[] ReadData(XmlReader reader)
    {
        reader.ReadStartElement("data");

        ArrayPool<byte> pool = ArrayPool<byte>.Shared;
        byte[] rented = pool.Rent(4096);
        int total = 0;

        while (true)
        {
            if (rented.Length - total < 1024)
            {
                byte[] bigger = pool.Rent(rented.Length * 2);
                Buffer.BlockCopy(rented, 0, bigger, 0, total);
                pool.Return(rented);
                rented = bigger;
            }

            int read = reader.ReadContentAsBase64(rented, total, rented.Length - total);
            if (read == 0)
                break;
            total += read;
        }

        reader.ReadEndElement(); // </data>

        byte[] result = new byte[total];
        Buffer.BlockCopy(rented, 0, result, 0, total);
        pool.Return(rented);
        return result;
    }

    private static object[] ReadArray(XmlReader reader)
    {
        reader.ReadStartElement("array");

        List<object> list = new List<object>();

        while (reader.NodeType == XmlNodeType.Element)
            list.Add(ReadValue(reader));

        reader.ReadEndElement(); // </array>
        return list.Count == 0 ? [] : list.ToArray();
    }

    private static void WriteValue(XmlWriter writer, object value)
    {
        switch (value)
        {
            case string strVal:
                writer.WriteElementString("string", strVal);
                break;

            case bool boolVal:
                writer.WriteStartElement(boolVal ? "true" : "false"); // <true/> / <false/>
                writer.WriteEndElement();
                break;

            case byte[] byteArrVal:
                writer.WriteStartElement("data");
                writer.WriteBase64(byteArrVal, 0, byteArrVal.Length);
                writer.WriteEndElement();
                break;

            case string[] strArrVal:
                WriteArray(writer, strArrVal);
                break;

            case object[] objArrVal:
                WriteArray(writer, objArrVal);
                break;

            case Dictionary<string, object> dictVal:
                WriteDictionary(writer, dictVal);
                break;

            case double doubleVal:
                writer.WriteStartElement("real");
                writer.WriteString(doubleVal.ToString("R", CultureInfo.InvariantCulture));
                writer.WriteEndElement();
                break;

            case float floatVal:
                writer.WriteStartElement("real");
                writer.WriteString(floatVal.ToString("R", CultureInfo.InvariantCulture));
                writer.WriteEndElement();
                break;

            default:
                throw new InvalidOperationException($"Unsupported data type: {value.GetType().Name}");
        }
    }

    private static void WriteDictionary(XmlWriter writer, Dictionary<string, object> dict)
    {
        writer.WriteStartElement("dict");

        foreach (KeyValuePair<string, object> pair in dict)
        {
            writer.WriteElementString("key", pair.Key);
            WriteValue(writer, pair.Value);
        }

        writer.WriteEndElement(); // </dict>
    }

    private static void WriteArray(XmlWriter writer, IEnumerable<object> items)
    {
        writer.WriteStartElement("array");

        foreach (object item in items)
            WriteValue(writer, item);

        writer.WriteEndElement(); // </array>
    }
}